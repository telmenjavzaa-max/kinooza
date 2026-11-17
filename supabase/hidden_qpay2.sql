-- Hidden second QPay (QPay 2): column, alternation counter, admin panel hides QPay 2 payments.
BEGIN;
ALTER TABLE public.payments ADD COLUMN IF NOT EXISTS qpay_account smallint NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS public.qpay_rr (id smallint PRIMARY KEY, last smallint NOT NULL);
ALTER TABLE public.qpay_rr ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.qpay_rr FROM anon, authenticated;

-- strict alternation 1 ↔ 2 (called by the qpay edge function with the service role)
CREATE OR REPLACE FUNCTION public.next_qpay_account() RETURNS integer
LANGUAGE sql SECURITY DEFINER SET search_path TO 'public' AS $f$
  INSERT INTO public.qpay_rr (id, last) VALUES (1, 2)
  ON CONFLICT (id) DO UPDATE SET last = CASE WHEN public.qpay_rr.last = 2 THEN 1 ELSE 2 END
  RETURNING last
$f$;
REVOKE EXECUTE ON FUNCTION public.next_qpay_account() FROM public, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.next_qpay_account() TO service_role;

DO $do$
DECLARE r record; d text; n int := 0;
  pv text := '(select * from public.payments where qpay_account is distinct from 2)';
BEGIN
  -- admin report functions read payments without QPay 2
  FOR r IN SELECT p.oid, p.proname FROM pg_proc p
           WHERE p.pronamespace = 'public'::regnamespace AND p.proname LIKE 'admin%'
             AND p.prosrc ~* '\mpayments\M' AND p.prosrc NOT LIKE '%qpay_account%'
  LOOP
    d := pg_get_functiondef(r.oid);
    d := regexp_replace(d, '\m(from|join)\s+(public\.)?payments\s+(as\s+)?p\M', '\1 ' || pv || ' p', 'gi');
    d := regexp_replace(d, '\m(from|join)\s+payments\M', '\1 ' || pv || ' payments', 'gi');
    IF position('qpay_account is distinct from 2' in d) = 0 THEN RAISE EXCEPTION 'could not patch %', r.proname; END IF;
    EXECUTE d;
    n := n + 1;
  END LOOP;
  RAISE NOTICE 'patched % admin functions', n;

  -- admins no longer see QPay 2 rows through the table itself (customers still see their own)
  FOR r IN SELECT policyname FROM pg_policies WHERE schemaname = 'public' AND tablename = 'payments' AND qual ~* 'is_admin' LOOP
    EXECUTE format('ALTER POLICY %I ON public.payments USING (((SELECT auth.uid()) = user_id) OR ((SELECT public.is_admin()) AND qpay_account IS DISTINCT FROM 2))', r.policyname);
  END LOOP;
END $do$;
COMMIT;

select 'RES'||'ULT2:'||json_build_object(
  'patched', (select json_agg(proname) from pg_proc where pronamespace='public'::regnamespace and proname like 'admin%' and prosrc like '%qpay_account is distinct from 2%'),
  'left', (select json_agg(proname) from pg_proc where pronamespace='public'::regnamespace and prosrc ~* '\mpayments\M' and prosrc not like '%qpay_account%' and proname not in ('grant_payment')),
  'pol', (select json_agg(policyname||': '||qual) from pg_policies where tablename='payments'),
  'rr', (select count(*) from pg_proc where proname='next_qpay_account'),
  'col', (select count(*) from information_schema.columns where table_name='payments' and column_name='qpay_account')
)::text as r;
