-- Pear: запустите один раз в SQL Editor НОВОГО проекта Supabase.
-- Клиент НЕ должен получать service_role key.
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique check (username ~ '^[a-z0-9_]{3,24}$'),
  display_name text not null check (length(display_name) between 1 and 40),
  about text not null default '' check (length(about) <= 100),
  avatar_path text
);
create table if not exists public.messages (
  id bigint generated always as identity primary key,
  sender_id uuid not null references public.profiles(id) on delete cascade,
  recipient_id uuid not null references public.profiles(id) on delete cascade,
  body text not null check (length(trim(body)) between 1 and 2000),
  created_at timestamptz not null default now(),
  check (sender_id <> recipient_id)
);
create index if not exists pear_messages_sender on public.messages(sender_id,created_at);
create index if not exists pear_messages_recipient on public.messages(recipient_id,created_at);
alter table public.profiles enable row level security;
alter table public.messages enable row level security;
revoke all on public.profiles, public.messages from anon, authenticated;
grant select on public.profiles to authenticated;
grant update (display_name, about, avatar_path) on public.profiles to authenticated;
grant select on public.messages to authenticated;
grant insert (sender_id, recipient_id, body) on public.messages to authenticated;
grant usage, select on sequence public.messages_id_seq to authenticated;
create policy pear_profiles_read on public.profiles for select to authenticated using (true);
create policy pear_profiles_update on public.profiles for update to authenticated using (id = (select auth.uid())) with check (id = (select auth.uid()) and (avatar_path is null or split_part(avatar_path,'/',1) = (select auth.uid())::text));
create policy pear_messages_read on public.messages for select to authenticated using (sender_id = (select auth.uid()) or recipient_id = (select auth.uid()));
create policy pear_messages_insert on public.messages for insert to authenticated with check (sender_id = (select auth.uid()) and recipient_id <> (select auth.uid()));
-- Триггер создаёт профиль из логина, привязанного к адресу Auth.
-- Это учебная схема только для проекта Pear, не смешивайте с другими методами регистрации.
create or replace function public.pear_create_profile() returns trigger language plpgsql security definer set search_path = '' as $$
declare handle text;
begin
  if new.email is null or lower(split_part(new.email,'@',2)) <> 'pear-login.example.com' then
    raise exception 'Pear accepts only its username login alias';
  end if;
  handle := lower(split_part(new.email,'@',1));
  if handle !~ '^[a-z0-9_]{3,24}$' then raise exception 'Invalid username'; end if;
  insert into public.profiles(id, username, display_name) values (new.id,handle,handle);
  return new;
end $$;
revoke all on function public.pear_create_profile() from public, anon, authenticated;
create trigger pear_on_auth_user_created after insert on auth.users for each row execute function public.pear_create_profile();
-- Публичные аватары: URL фотографии доступен всем, кому он известен.
insert into storage.buckets (id,name,public,file_size_limit,allowed_mime_types)
values ('avatars','avatars',true,2097152,array['image/jpeg','image/png','image/webp'])
on conflict (id) do update set public=true,file_size_limit=2097152,allowed_mime_types=array['image/jpeg','image/png','image/webp'];
create policy pear_avatar_upload on storage.objects for insert to authenticated with check (bucket_id='avatars' and (storage.foldername(name))[1]=(select auth.uid())::text);
create policy pear_avatar_delete on storage.objects for delete to authenticated using (bucket_id='avatars' and (storage.foldername(name))[1]=(select auth.uid())::text);
