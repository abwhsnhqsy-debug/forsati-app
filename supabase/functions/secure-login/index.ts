
import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function respond(body: Record<string, unknown>, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json",
    },
  });
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return respond({ error: "Method not allowed" }, 405);
  }

  let email = "";
  let password = "";

  try {
    const body = await req.json();
    email =
      typeof body.email === "string"
        ? body.email.trim().toLowerCase()
        : "";
    password =
      typeof body.password === "string" ? body.password : "";
  } catch {
    return respond({ error: "بيانات الدخول غير صحيحة." }, 400);
  }

  if (
    !email ||
    email.length > 254 ||
    !password ||
    password.length > 1024
  ) {
    return respond(
      { error: "أدخل البريد الإلكتروني وكلمة المرور." },
      400,
    );
  }

  const url = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

  if (!url || !anonKey || !serviceKey) {
    console.error("Missing Supabase environment variables");
    return respond({ error: "الخدمة غير جاهزة حاليًا." }, 500);
  }

  const admin = createClient(url, serviceKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  });

  try {
    const { data: lock, error: lockError } = await admin.rpc(
      "check_login_lock",
      { p_email: email },
    );

    if (lockError) {
      console.error("Lock check failed:", lockError.message);
      return respond({ error: "تعذّر تسجيل الدخول حاليًا." }, 500);
    }

    if (lock?.locked) {
      return respond(
        {
          locked: true,
          retry_after_seconds: lock.retry_after_seconds ?? 900,
          error: "تم قفل تسجيل الدخول لمدة 15 دقيقة.",
        },
        429,
      );
    }

    const auth = createClient(url, anonKey, {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
    });

    const { data, error } = await auth.auth.signInWithPassword({
      email,
      password,
    });

    if (error || !data.session) {
      const { data: failure, error: failureError } =
        await admin.rpc("record_login_failure", {
          p_email: email,
        });

      if (failureError) {
        console.error(
          "Failure counter update failed:",
          failureError.message,
        );
        return respond(
          { error: "تعذّر تسجيل الدخول حاليًا." },
          500,
        );
      }

      if (failure?.locked) {
        return respond(
          {
            locked: true,
            retry_after_seconds: 900,
            error: "تم قفل تسجيل الدخول لمدة 15 دقيقة.",
          },
          429,
        );
      }

      return respond(
        {
          error: "البريد الإلكتروني أو كلمة المرور غير صحيحة.",
          attempts_remaining: failure?.attempts_remaining,
        },
        401,
      );
    }

    const { error: clearError } = await admin.rpc(
      "clear_login_failures",
      { p_email: email },
    );

    if (clearError) {
      console.error(
        "Could not clear failed attempts:",
        clearError.message,
      );
    }

    return respond({
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      token_type: data.session.token_type,
      expires_in: data.session.expires_in,
      user: data.user,
    });
  } catch (error) {
    console.error(
      "Secure login error:",
      error instanceof Error ? error.message : "unknown",
    );
    return respond(
      { error: "تعذّر تسجيل الدخول حاليًا." },
      500,
    );
  }
});
    
