-- 1. Herkese açık kullanıcı profilleri tablosu
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text unique not null,
  email text,
  target_department text default 'İTÜ 2027',
  bio text default 'İTÜ 2027 hedefiyle çalışıyor.',
  avatar_url text,
  banned boolean default false,
  created_at timestamptz default now()
);

-- Eğer tablo daha önce oluşturulduysa email sütununu güvenli şekilde ekle
alter table public.profiles add column if not exists email text;

-- 2. Row Level Security (RLS) aktif et
alter table public.profiles enable row level security;

-- 3. Herkes profilleri görebilir (Giriş yapmamış ziyaretçiler dahil)
drop policy if exists "Herkes profilleri okuyabilir" on public.profiles;
create policy "Herkes profilleri okuyabilir"
on public.profiles for select
using (true);

-- 4. Kullanıcı yalnızca kendi profil satırını oluşturabilir
drop policy if exists "Kullanıcı kendi profilini ekleyebilir" on public.profiles;
create policy "Kullanıcı kendi profilini ekleyebilir"
on public.profiles for insert
with check (auth.uid() = id);

-- 5. Kullanıcı yalnızca kendi profilini güncelleyebilir
drop policy if exists "Kullanıcı kendi profilini güncelleyebilir" on public.profiles;
create policy "Kullanıcı kendi profilini güncelleyebilir"
on public.profiles for update
using (auth.uid() = id)
with check (auth.uid() = id);