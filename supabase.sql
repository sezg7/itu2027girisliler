-- 1. Herkese açık kullanıcı profilleri tablosu
begin;

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
alter table public.profiles add column if not exists is_admin boolean not null default false;

-- 2. Row Level Security (RLS) aktif et
alter table public.profiles enable row level security;
revoke select on public.profiles from public, anon, authenticated;
grant select (id, username, target_department, bio, avatar_url, banned, is_admin, created_at)
  on public.profiles to anon, authenticated;
revoke insert on public.profiles from authenticated;

-- 3. Herkes profilleri görebilir (Giriş yapmamış ziyaretçiler dahil)
drop policy if exists profiles_select_all on public.profiles;
drop policy if exists "Herkes profilleri okuyabilir" on public.profiles;
create policy "Herkes profilleri okuyabilir"
on public.profiles for select
using (true);

-- Auth trigger creates profiles; clients must not insert arbitrary profile rows.
drop policy if exists profiles_insert_own on public.profiles;
drop policy if exists "Kullanıcı kendi profilini ekleyebilir" on public.profiles;

-- 5. Kullanıcı yalnızca kendi profilini güncelleyebilir
drop policy if exists profiles_update_own on public.profiles;
drop policy if exists "Kullanıcı kendi profilini güncelleyebilir" on public.profiles;
create policy "Kullanıcı kendi profilini güncelleyebilir"
on public.profiles for update
using (auth.uid() = id)
with check (auth.uid() = id);

-- Role is managed in SQL, never by profile form submissions.
revoke update on public.profiles from authenticated;
grant update (username, email, target_department, bio, avatar_url) on public.profiles to authenticated;

create or replace function public.is_club_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles
    where id = (select auth.uid()) and is_admin and not coalesce(banned, false)
  );
$$;
grant execute on function public.is_club_admin() to anon, authenticated;

do $migration$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'profiles' and column_name = 'photo_url'
  ) and exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'profiles' and column_name = 'avatar'
  ) and exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'profiles' and column_name = 'nick'
  ) and exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'profiles' and column_name = 'username'
  ) then
    execute $function$
      create or replace function public.sync_all_profile_photos()
      returns trigger
      language plpgsql
      security definer
      set search_path = public
      as $body$
      declare
        latest_photo text;
      begin
        if tg_op = 'INSERT' then
          latest_photo := coalesce(
            nullif(trim(new.photo_url), ''),
            nullif(trim(new.avatar_url), ''),
            nullif(trim(new.avatar), '')
          );
          new.avatar := coalesce(latest_photo, '');
          new.avatar_url := latest_photo;
          new.photo_url := latest_photo;
          if new.nick is null or btrim(new.nick) = '' then new.nick := new.username; end if;
          if new.username is null or btrim(new.username) = '' then new.username := new.nick; end if;
          return new;
        end if;

        if new.photo_url is distinct from old.photo_url and nullif(trim(new.photo_url), '') is not null then
          latest_photo := trim(new.photo_url);
        elsif new.avatar_url is distinct from old.avatar_url and nullif(trim(new.avatar_url), '') is not null then
          latest_photo := trim(new.avatar_url);
        elsif new.avatar is distinct from old.avatar and nullif(trim(new.avatar), '') is not null then
          latest_photo := trim(new.avatar);
        else
          latest_photo := coalesce(
            nullif(trim(new.photo_url), ''),
            nullif(trim(new.avatar_url), ''),
            nullif(trim(new.avatar), '')
          );
        end if;

        if latest_photo is not null then
          new.avatar := latest_photo;
          new.avatar_url := latest_photo;
          new.photo_url := latest_photo;
        else
          new.avatar := coalesce(nullif(trim(old.avatar), ''), '');
          new.avatar_url := coalesce(nullif(trim(old.avatar_url), ''), nullif(trim(old.photo_url), ''), nullif(trim(old.avatar), ''));
          new.photo_url := new.avatar_url;
        end if;
        if new.nick is null or btrim(new.nick) = '' then new.nick := old.nick; end if;
        if new.username is null or btrim(new.username) = '' then new.username := new.nick; end if;
        return new;
      end;
      $body$;
    $function$;
  end if;
end;
$migration$;

-- Backfill missing profiles without changing existing profiles or auth users.
do $$
declare
  auth_row record;
  new_username text;
begin
  for auth_row in
    select u.id, u.email, u.raw_user_meta_data
    from auth.users u
    where not exists (select 1 from public.profiles p where p.id = u.id)
    order by u.created_at
  loop
    new_username := lower(regexp_replace(
      coalesce(auth_row.raw_user_meta_data->>'username', split_part(auth_row.email, '@', 1)),
      '[^a-z0-9._-]', '', 'g'
    ));
    if new_username = '' or exists (
      select 1 from public.profiles p where lower(p.username) = new_username
    ) then
      new_username := 'uye_' || left(auth_row.id::text, 8);
    end if;
    if exists (
      select 1 from information_schema.columns
      where table_schema = 'public' and table_name = 'profiles' and column_name = 'nick'
    ) then
      execute 'insert into public.profiles (id, nick, username, email, target_department, bio, avatar_url)
        values ($1, $2, $2, $3, $4, $5, $6) on conflict (id) do nothing'
      using
        auth_row.id,
        new_username,
        auth_row.email,
        coalesce(auth_row.raw_user_meta_data->>'target_department', 'İTÜ 2027'),
        coalesce(auth_row.raw_user_meta_data->>'bio', 'İTÜ 2027 hedefiyle çalışıyor.'),
        auth_row.raw_user_meta_data->>'avatar_url';
    else
      insert into public.profiles (id, username, email, target_department, bio, avatar_url)
      values (
        auth_row.id,
        new_username,
        auth_row.email,
        coalesce(auth_row.raw_user_meta_data->>'target_department', 'İTÜ 2027'),
        coalesce(auth_row.raw_user_meta_data->>'bio', 'İTÜ 2027 hedefiyle çalışıyor.'),
        auth_row.raw_user_meta_data->>'avatar_url'
      )
      on conflict (id) do nothing;
    end if;
  end loop;
end;
$$;

-- Existing "wizard" profile becomes the site administrator; no account changes.
update public.profiles set is_admin = true where lower(username) = 'wizard';
update public.profiles p
set email = u.email
from auth.users u
where u.id = p.id and p.email is distinct from u.email;

-- Ensure future auth users get a profile even when email confirmation is on.
create or replace function public.handle_new_auth_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  requested_username text;
begin
  requested_username := lower(regexp_replace(
    coalesce(new.raw_user_meta_data->>'username', split_part(new.email, '@', 1)),
    '[^a-z0-9._-]', '', 'g'
  ));
  if requested_username = '' or exists (
    select 1 from public.profiles p
    where lower(p.username) = requested_username and p.id <> new.id
  ) then
    requested_username := 'uye_' || left(new.id::text, 8);
  end if;
  if exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'profiles' and column_name = 'nick'
  ) then
    execute 'insert into public.profiles (id, nick, username, email, target_department, bio, avatar_url)
      values ($1, $2, $2, $3, $4, $5, $6) on conflict (id) do nothing'
    using
      new.id,
      requested_username,
      new.email,
      coalesce(new.raw_user_meta_data->>'target_department', 'İTÜ 2027'),
      coalesce(new.raw_user_meta_data->>'bio', 'İTÜ 2027 hedefiyle çalışıyor.'),
      new.raw_user_meta_data->>'avatar_url';
  else
    insert into public.profiles (id, username, email, target_department, bio, avatar_url)
    values (
      new.id,
      requested_username,
      new.email,
      coalesce(new.raw_user_meta_data->>'target_department', 'İTÜ 2027'),
      coalesce(new.raw_user_meta_data->>'bio', 'İTÜ 2027 hedefiyle çalışıyor.'),
      new.raw_user_meta_data->>'avatar_url'
    )
    on conflict (id) do nothing;
  end if;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_profile on auth.users;
create trigger on_auth_user_created_profile
after insert on auth.users
for each row execute procedure public.handle_new_auth_user();

-- Password sign-in uses email in Supabase Auth; this supports the existing
-- username login screen without changing accounts or passwords.
create or replace function public.lookup_auth_email_by_username(input_username text)
returns text
language sql
stable
security definer
set search_path = public
as $$
  select email
  from public.profiles
  where lower(username) = lower(regexp_replace(trim(input_username), '^@+', ''))
  limit 1;
$$;
grant execute on function public.lookup_auth_email_by_username(text) to anon, authenticated;

-- Shared application records. Personal results remain private to their owner.
create table if not exists public.club_records (
  id text primary key,
  kind text not null check (kind in (
    'exam', 'participant', 'score', 'personal_result',
    'question', 'question_like', 'question_comment',
    'desk', 'desk_like', 'desk_comment', 'chat', 'feedback'
  )),
  owner_id uuid references public.profiles(id) on delete cascade,
  target_id text,
  visibility text not null default 'public' check (visibility in ('public', 'private')),
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  constraint private_records_are_private check (
    (kind in ('personal_result', 'feedback') and visibility = 'private')
    or (kind not in ('personal_result', 'feedback') and visibility = 'public')
  )
);
create index if not exists club_records_kind_created_idx
  on public.club_records (kind, created_at desc);
create index if not exists club_records_owner_idx
  on public.club_records (owner_id);
create index if not exists club_records_target_idx
  on public.club_records (kind, target_id);
alter table public.club_records enable row level security;
grant select on public.club_records to anon, authenticated;
grant insert, update, delete on public.club_records to authenticated;

drop policy if exists "Herkes ortak kayıtları ve kendi özel kayıtlarını okuyabilir" on public.club_records;
create policy "Herkes ortak kayıtları ve kendi özel kayıtlarını okuyabilir"
on public.club_records for select
using (
  visibility = 'public'
  or owner_id = (select auth.uid())
  or (kind = 'feedback' and public.is_club_admin())
);

drop policy if exists "Üyeler kayıt ekleyebilir" on public.club_records;
create policy "Üyeler kayıt ekleyebilir"
on public.club_records for insert
with check (
  owner_id = (select auth.uid())
  and (kind <> 'exam' or public.is_club_admin())
);

drop policy if exists "Üyeler kendi kayıtlarını güncelleyebilir" on public.club_records;
create policy "Üyeler kendi kayıtlarını güncelleyebilir"
on public.club_records for update
using (owner_id = (select auth.uid()) or public.is_club_admin())
with check (
  (owner_id = (select auth.uid()) or public.is_club_admin())
  and (kind <> 'exam' or public.is_club_admin())
);

drop policy if exists "Üyeler kendi kayıtlarını silebilir" on public.club_records;
create policy "Üyeler kendi kayıtlarını silebilir"
on public.club_records for delete
using (
  public.is_club_admin()
  or (
    owner_id = (select auth.uid())
    and kind in ('personal_result', 'question_like', 'desk_like')
  )
);

-- Public media is stored in Supabase Storage, not in localStorage/profile rows.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('club-media', 'club-media', true, 5242880, array['image/jpeg', 'image/png', 'image/webp'])
on conflict (id) do update set
  public = excluded.public,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "Herkes kulüp görsellerini görebilir" on storage.objects;
create policy "Herkes kulüp görsellerini görebilir"
on storage.objects for select
using (bucket_id = 'club-media');

drop policy if exists "Üyeler kendi kulüp görsellerini yükleyebilir" on storage.objects;
create policy "Üyeler kendi kulüp görsellerini yükleyebilir"
on storage.objects for insert to authenticated
with check (
  bucket_id = 'club-media'
  and (storage.foldername(name))[1] = (select auth.uid())::text
);

drop policy if exists "Üyeler kendi kulüp görsellerini güncelleyebilir" on storage.objects;
create policy "Üyeler kendi kulüp görsellerini güncelleyebilir"
on storage.objects for update to authenticated
using (
  bucket_id = 'club-media'
  and (storage.foldername(name))[1] = (select auth.uid())::text
)
with check (
  bucket_id = 'club-media'
  and (storage.foldername(name))[1] = (select auth.uid())::text
);

drop policy if exists "Üyeler kendi kulüp görsellerini silebilir" on storage.objects;
create policy "Üyeler kendi kulüp görsellerini silebilir"
on storage.objects for delete to authenticated
using (
  bucket_id = 'club-media'
  and (storage.foldername(name))[1] = (select auth.uid())::text
);

-- Seed the existing default schedule once; rerunning does not overwrite edits.
insert into public.club_records (id, kind, owner_id, payload)
values
  ('tyt-1', 'exam', null, '{"name":"TYT Genel Deneme 01","type":"TYT","maxQ":120,"date":"2027-01-16","pdfUrl":"","videoUrl":""}'::jsonb),
  ('ayt-1', 'exam', null, '{"name":"AYT Genel Deneme 01","type":"AYT","maxQ":80,"date":"2027-02-13","pdfUrl":"","videoUrl":""}'::jsonb),
  ('brans-1', 'exam', null, '{"name":"AYT Matematik Ortak Denemesi","type":"BRANŞ","maxQ":40,"date":"2027-03-06","pdfUrl":"","videoUrl":""}'::jsonb)
on conflict (id) do nothing;

notify pgrst, 'reload schema';
commit;