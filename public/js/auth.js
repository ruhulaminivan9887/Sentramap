/* ============== Supabase Auth ==============
   Loaded on the page via CDN script tag (see index.html).
   Handles: sign up, log in, Google OAuth, session persistence, logout. */

let supabaseClient = null;
let currentUser = null;
let currentSession = null;

async function initAuth(supabaseUrl, supabaseAnonKey) {
  supabaseClient = window.supabase.createClient(supabaseUrl, supabaseAnonKey);

  const { data: { session } } = await supabaseClient.auth.getSession();
  currentSession = session;
  currentUser = session?.user || null;

  supabaseClient.auth.onAuthStateChange((event, session) => {
    currentSession = session;
    currentUser = session?.user || null;
    onAuthChange(currentUser);
  });

  onAuthChange(currentUser);
}

async function signUpEmail(email, password) {
  return supabaseClient.auth.signUp({ email, password });
}

async function signInEmail(email, password) {
  return supabaseClient.auth.signInWithPassword({ email, password });
}

async function signInGoogle() {
  return supabaseClient.auth.signInWithOAuth({
    provider: 'google',
    options: { redirectTo: window.location.origin }
  });
}

async function signOut() {
  await supabaseClient.auth.signOut();
}

async function requestPasswordReset(email) {
  return supabaseClient.auth.resetPasswordForEmail(email, {
    redirectTo: window.location.origin
  });
}

async function updatePassword(newPassword) {
  return supabaseClient.auth.updateUser({ password: newPassword });
}

function isPasswordRecoverySession() {
  return window.location.hash.includes('type=recovery');
}

function getAccessToken() {
  return currentSession?.access_token || null;
}

function getCurrentUser() {
  return currentUser;
}

// Overridden in app.js to update the UI whenever login state changes.
function onAuthChange(user) { /* no-op placeholder */ }
