-- Кабінет викладача: таблиці для синхронізації викладача й учнів.
-- Вставте цей скрипт у Supabase → SQL Editor → New query і натисніть Run.
-- Скрипт можна запускати повторно: він нічого не видаляє.

-- Усі дані викладача (учні, розклад, уроки, матеріали, завдання) одним документом.
-- version захищає від того, щоб два пристрої затирали зміни одне одного.
create table if not exists workspaces (
  teacher_id bigint primary key,            -- Telegram ID викладача
  data jsonb not null,
  version integer not null default 1,
  updated_at timestamptz not null default now()
);

-- Коди запрошень: посилання t.me/<бот>?startapp=s_<code> веде до конкретного учня.
create table if not exists invites (
  code text primary key,
  teacher_id bigint not null references workspaces(teacher_id) on delete cascade,
  student_id text not null
);

-- Який Telegram-акаунт є яким учнем. Один учень може мати кількох викладачів.
create table if not exists links (
  tg_id bigint not null,                    -- Telegram ID учня
  teacher_id bigint not null references workspaces(teacher_id) on delete cascade,
  student_id text not null,
  created_at timestamptz not null default now(),
  primary key (tg_id, teacher_id)
);
-- Перехід зі старої схеми, де учень мав лише одного викладача.
do $$ begin
  if (select count(*) from information_schema.key_column_usage
      where table_name = 'links' and constraint_name = 'links_pkey') = 1 then
    alter table links drop constraint links_pkey;
    alter table links add constraint links_pkey primary key (tg_id, teacher_id);
  end if;
end $$;

-- Викладачі та їхні запити на доступ. Адміністратори (секрет TEACHER_IDS)
-- підтверджують або відхиляють запити в налаштуваннях апки.
create table if not exists teachers (
  tg_id bigint primary key,
  name text not null default '',
  username text not null default '',
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
  created_at timestamptz not null default now(),
  decided_at timestamptz
);

-- Дії учнів (виконане ДЗ, запит на перенесення, підключення).
-- Апка викладача забирає їх, переносить у свої дані й позначає applied.
create table if not exists student_actions (
  id bigserial primary key,
  teacher_id bigint not null references workspaces(teacher_id) on delete cascade,
  student_id text not null,
  kind text not null,
  payload jsonb not null default '{}'::jsonb,
  applied boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists student_actions_pending on student_actions (teacher_id) where not applied;

-- Прямого доступу з браузера немає: увімкнений RLS без жодних правил.
-- Читати й писати може лише серверна функція api, яка перевіряє підпис Telegram.
alter table workspaces enable row level security;
alter table invites enable row level security;
alter table links enable row level security;
alter table teachers enable row level security;
alter table student_actions enable row level security;
