-- me0w backend schema. Supabase dashboard > SQL Editor > New query > paste > Run.

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null check (username ~ '^[A-Za-z0-9_.]{3,20}$'),
  created_at timestamptz not null default now()
);
create unique index profiles_username_key on public.profiles (lower(username));

create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, username)
  values (new.id, coalesce(new.raw_user_meta_data->>'username', 'user' || substr(new.id::text, 1, 6)));
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

create table public.servers (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 40),
  owner_id uuid not null references public.profiles(id),
  invite_code text not null unique default substr(md5(random()::text || clock_timestamp()::text), 1, 8),
  created_at timestamptz not null default now()
);
create table public.members (
  server_id uuid references public.servers(id) on delete cascade,
  user_id uuid references public.profiles(id) on delete cascade,
  joined_at timestamptz not null default now(),
  primary key (server_id, user_id)
);
create table public.channels (
  id uuid primary key default gen_random_uuid(),
  server_id uuid not null references public.servers(id) on delete cascade,
  name text not null check (char_length(name) between 1 and 30),
  created_at timestamptz not null default now()
);
create table public.messages (
  id bigint generated always as identity primary key,
  channel_id uuid not null references public.channels(id) on delete cascade,
  user_id uuid not null default auth.uid() references public.profiles(id),
  content text not null check (char_length(content) between 1 and 2000),
  created_at timestamptz not null default now()
);
create index messages_channel_idx on public.messages (channel_id, id desc);
create table public.friendships (
  id bigint generated always as identity primary key,
  requester uuid not null default auth.uid() references public.profiles(id),
  addressee uuid not null references public.profiles(id),
  status text not null default 'pending' check (status in ('pending', 'accepted')),
  created_at timestamptz not null default now(),
  unique (requester, addressee),
  check (requester <> addressee)
);

-- helpers used by the security policies
create function public.is_member(sid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from members where server_id = sid and user_id = auth.uid());
$$;
create function public.can_read_channel(cid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from channels c join members m on m.server_id = c.server_id
                 where c.id = cid and m.user_id = auth.uid());
$$;

-- row level security: nobody sees anything unless a policy allows it
alter table public.profiles    enable row level security;
alter table public.servers     enable row level security;
alter table public.members     enable row level security;
alter table public.channels    enable row level security;
alter table public.messages    enable row level security;
alter table public.friendships enable row level security;

create policy profiles_read   on public.profiles for select to authenticated using (true);
create policy servers_read    on public.servers  for select to authenticated using (public.is_member(id));
create policy servers_owner   on public.servers  for update to authenticated using (owner_id = auth.uid());
create policy servers_delete  on public.servers  for delete to authenticated using (owner_id = auth.uid());
create policy members_read    on public.members  for select to authenticated using (public.is_member(server_id));
create policy members_leave   on public.members  for delete to authenticated using (user_id = auth.uid());
create policy channels_read   on public.channels for select to authenticated using (public.is_member(server_id));
create policy channels_create on public.channels for insert to authenticated
  with check (exists (select 1 from public.servers s where s.id = server_id and s.owner_id = auth.uid()));
create policy messages_read   on public.messages for select to authenticated using (public.can_read_channel(channel_id));
create policy messages_send   on public.messages for insert to authenticated
  with check (user_id = auth.uid() and public.can_read_channel(channel_id));
create policy messages_delete on public.messages for delete to authenticated using (user_id = auth.uid());
create policy friends_read    on public.friendships for select to authenticated using (auth.uid() in (requester, addressee));
create policy friends_accept  on public.friendships for update to authenticated
  using (addressee = auth.uid()) with check (addressee = auth.uid());
create policy friends_remove  on public.friendships for delete to authenticated using (auth.uid() in (requester, addressee));

-- actions that need to write several tables at once
create function public.create_server(sname text) returns uuid
language plpgsql security definer set search_path = public as $$
declare sid uuid;
begin
  if auth.uid() is null then raise exception 'Not signed in'; end if;
  insert into servers (name, owner_id) values (trim(sname), auth.uid()) returning id into sid;
  insert into members (server_id, user_id) values (sid, auth.uid());
  insert into channels (server_id, name) values (sid, 'general');
  return sid;
end $$;

create function public.join_server(code text) returns uuid
language plpgsql security definer set search_path = public as $$
declare sid uuid;
begin
  if auth.uid() is null then raise exception 'Not signed in'; end if;
  select id into sid from servers where invite_code = lower(trim(code));
  if sid is null then raise exception 'Invalid invite code'; end if;
  insert into members (server_id, user_id) values (sid, auth.uid()) on conflict do nothing;
  return sid;
end $$;

create function public.add_friend(uname text) returns text
language plpgsql security definer set search_path = public as $$
declare tid uuid;
begin
  if auth.uid() is null then raise exception 'Not signed in'; end if;
  select id into tid from profiles where lower(username) = lower(trim(uname));
  if tid is null then raise exception 'User not found'; end if;
  if tid = auth.uid() then raise exception 'You cannot add yourself'; end if;
  update friendships set status = 'accepted'
    where requester = tid and addressee = auth.uid() and status = 'pending';
  if found then return 'accepted'; end if;
  if exists (select 1 from friendships
             where (requester = auth.uid() and addressee = tid) or (requester = tid and addressee = auth.uid())) then
    raise exception 'Already friends or request already sent';
  end if;
  insert into friendships (requester, addressee) values (auth.uid(), tid);
  return 'sent';
end $$;

revoke execute on function public.create_server(text), public.join_server(text), public.add_friend(text) from public, anon;
grant  execute on function public.create_server(text), public.join_server(text), public.add_friend(text) to authenticated;

-- realtime for live messages and friend requests
alter publication supabase_realtime add table public.messages, public.friendships;
