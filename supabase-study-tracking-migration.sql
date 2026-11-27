begin;

alter table public.club_records
  drop constraint if exists club_records_kind_check;
alter table public.club_records
  add constraint club_records_kind_check check (kind in (
    'exam', 'participant', 'score', 'personal_result', 'study_session',
    'question', 'question_like', 'question_comment',
    'desk', 'desk_like', 'desk_comment', 'chat', 'feedback'
  ));

alter table public.club_records
  drop constraint if exists private_records_are_private;
alter table public.club_records
  add constraint private_records_are_private check (
    (kind in ('personal_result', 'study_session', 'feedback') and visibility = 'private')
    or (kind not in ('personal_result', 'study_session', 'feedback') and visibility = 'public')
  );

drop policy if exists "Üyeler kendi kayıtlarını silebilir" on public.club_records;
create policy "Üyeler kendi kayıtlarını silebilir"
on public.club_records for delete
using (
  public.is_club_admin()
  or (
    owner_id = (select auth.uid())
    and kind in ('personal_result', 'study_session', 'question_like', 'desk_like')
  )
);

create or replace function public.weekly_study_leaderboard(p_week_start date)
returns table (username text, total_seconds bigint)
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  with daily_totals as (
    select
      records.owner_id,
      least(
        86400::bigint,
        greatest(
          0::bigint,
          case
            when records.payload ->> 'seconds' ~ '^[0-9]{1,6}$'
              then (records.payload ->> 'seconds')::bigint
            else 0::bigint
          end
        )
      ) as seconds
    from public.club_records as records
    where auth.uid() is not null
      and records.kind = 'study_session'
      and records.visibility = 'private'
      and records.owner_id is not null
      and records.payload ->> 'studyDate' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'
      and records.payload ->> 'studyDate' >= p_week_start::text
      and records.payload ->> 'studyDate' <= (p_week_start + 6)::text
  )
  select profiles.username, sum(daily_totals.seconds)::bigint
  from daily_totals
  join public.profiles as profiles on profiles.id = daily_totals.owner_id
  where profiles.banned is not true
  group by profiles.id, profiles.username
  having sum(daily_totals.seconds) > 0
  order by sum(daily_totals.seconds) desc, lower(profiles.username)
  limit 50;
$$;
revoke all on function public.weekly_study_leaderboard(date) from public, anon;
grant execute on function public.weekly_study_leaderboard(date) to authenticated;

commit;
