-- Run this entire file once in Supabase Dashboard → SQL Editor.

create table if not exists public.users (
  discord_id text primary key,
  display_name text not null,
  avatar_url text not null,
  total_score integer not null default 0 check (total_score >= 0),
  questions_answered integer not null default 0 check (questions_answered >= 0),
  created_at timestamptz not null default now(),
  last_login_at timestamptz not null default now()
);

create table if not exists public.questions (
  id text primary key,
  prompt text not null,
  expected_answer text not null,
  points integer not null default 100 check (points >= 0),
  active_date date unique,
  created_at timestamptz not null default now()
);

create table if not exists public.attempts (
  id bigint generated always as identity primary key,
  discord_id text not null references public.users(discord_id) on delete cascade,
  question_id text not null references public.questions(id) on delete cascade,
  submitted_answer text not null,
  is_correct boolean not null,
  points_awarded integer not null default 0 check (points_awarded >= 0),
  answered_at timestamptz not null default now(),
  unique (discord_id, question_id)
);

create index if not exists users_leaderboard_idx
  on public.users (total_score desc, questions_answered desc);

create index if not exists attempts_user_idx
  on public.attempts (discord_id, answered_at desc);

alter table public.users enable row level security;
alter table public.questions enable row level security;
alter table public.attempts enable row level security;

-- The website backend uses the service-role key. Browser clients receive no
-- direct table access, preventing users from changing their own scores.
revoke all on public.users from anon, authenticated;
revoke all on public.questions from anon, authenticated;
revoke all on public.attempts from anon, authenticated;

create or replace function public.submit_answer(
  p_discord_id text,
  p_question_id text,
  p_answer text
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  selected_question public.questions%rowtype;
  answer_is_correct boolean;
  awarded_points integer;
begin
  select *
    into selected_question
    from public.questions
    where id = p_question_id;

  if not found then
    raise exception 'question not found';
  end if;

  answer_is_correct :=
    lower(trim(p_answer)) = lower(trim(selected_question.expected_answer));
  awarded_points := case when answer_is_correct then selected_question.points else 0 end;

  begin
    insert into public.attempts (
      discord_id,
      question_id,
      submitted_answer,
      is_correct,
      points_awarded
    )
    values (
      p_discord_id,
      p_question_id,
      p_answer,
      answer_is_correct,
      awarded_points
    );
  exception
    when unique_violation then
      raise exception 'already answered';
  end;

  update public.users
    set total_score = total_score + awarded_points,
        questions_answered = questions_answered + 1
    where discord_id = p_discord_id;

  return jsonb_build_object(
    'correct', answer_is_correct,
    'pointsAwarded', awarded_points,
    'correctAnswer', selected_question.expected_answer
  );
end;
$$;

revoke all on function public.submit_answer(text, text, text) from public;
grant execute on function public.submit_answer(text, text, text) to service_role;

-- Example question (replace with your real SAT question):
-- insert into public.questions (id, prompt, expected_answer, points, active_date)
-- values ('2026-07-30', 'What is 2 + 2?', '4', 100, '2026-07-30');
