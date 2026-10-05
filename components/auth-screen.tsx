'use client'

import { useState, type FormEvent } from 'react'
import { useRouter } from 'next/navigation'
import { ArrowRight, Check, ChevronRight, Fingerprint, Globe2, Link2, LockKeyhole, Mail, MessageSquareText, ShieldCheck, Smartphone } from 'lucide-react'
import { createClient, authRedirectUrl } from '@/lib/supabase/client'

type AuthMode = 'signin' | 'signup' | 'phone' | 'reset'

function friendlyAuthError(message: string) {
  const normalized = message.toLowerCase()
  if (normalized.includes('invalid login credentials') || normalized.includes('invalid email or password')) return 'Email or password is incorrect.'
  if (normalized.includes('email not confirmed')) return 'Confirm your email using the link we sent before signing in.'
  if (normalized.includes('password should be at least') || normalized.includes('weak_password')) return 'Choose a stronger password with at least 8 characters.'
  if (normalized.includes('rate limit') || normalized.includes('too many requests')) return 'Too many attempts. Wait a little and try again.'
  if (normalized.includes('provider is not enabled') || normalized.includes('unsupported provider') || normalized.includes('sms provider')) return 'This sign-in method is not enabled for this project yet.'
  if (normalized.includes('invalid email') || normalized.includes('email_address_invalid')) return 'Enter a valid email address.'
  return 'Authentication could not be completed. Check your details or try again later.'
}

export function AuthScreen() {
  const router = useRouter()
  const supabase = createClient()
  const [mode, setMode] = useState<AuthMode>('signin')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [phone, setPhone] = useState('')
  const [otp, setOtp] = useState('')
  const [otpSent, setOtpSent] = useState(false)
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')

  function clearFeedback() {
    setNotice('')
    setError('')
  }

  async function handleEmailAuth(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    clearFeedback()
    setBusy(true)
    try {
      if (mode === 'reset') {
        const { error: resetError } = await supabase.auth.resetPasswordForEmail(email, {
          redirectTo: `${window.location.origin}/auth/callback?next=/reset-password`,
        })
        if (resetError) throw resetError
        setNotice('If an account exists for that email, a password reset link is on its way.')
        return
      }

      if (mode === 'signup') {
        const { data, error: signUpError } = await supabase.auth.signUp({
          email,
          password,
          options: {
            emailRedirectTo: authRedirectUrl(),
            data: { display_name: email.split('@')[0] },
          },
        })
        if (signUpError) throw signUpError
        if (!data.session) {
          setNotice('Check your inbox to confirm your email address, then sign in.')
          return
        }
      } else {
        const { error: signInError } = await supabase.auth.signInWithPassword({ email, password })
        if (signInError) throw signInError
      }
      router.replace('/dashboard')
      router.refresh()
    } catch (cause) {
      setError(friendlyAuthError(cause instanceof Error ? cause.message : ''))
    } finally {
      setBusy(false)
    }
  }

  async function handleGoogle() {
    clearFeedback()
    setBusy(true)
    const { error: oauthError } = await supabase.auth.signInWithOAuth({
      provider: 'google',
      options: { redirectTo: authRedirectUrl() },
    })
    if (oauthError) {
      setBusy(false)
      setError(friendlyAuthError(oauthError.message))
    }
  }

  async function handlePhone(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    clearFeedback()
    setBusy(true)
    try {
      if (!otpSent) {
        const { error: otpError } = await supabase.auth.signInWithOtp({ phone })
        if (otpError) throw otpError
        setOtpSent(true)
        setNotice('A one-time code was sent to your phone.')
      } else {
        const { error: verifyError } = await supabase.auth.verifyOtp({ phone, token: otp, type: 'sms' })
        if (verifyError) throw verifyError
        router.replace('/dashboard')
        router.refresh()
      }
    } catch (cause) {
      setError(friendlyAuthError(cause instanceof Error ? cause.message : ''))
    } finally {
      setBusy(false)
    }
  }

  const heading = mode === 'signup' ? 'Create your account' : mode === 'phone' ? 'Sign in with phone' : mode === 'reset' ? 'Reset your password' : 'Welcome back'

  return (
    <main className="auth-page">
      <section className="auth-story" aria-label="Phishing Shield security platform">
        <div className="auth-story-inner">
          <a className="brand-lockup" href="/" aria-label="Phishing Shield home">
            <span className="brand-mark"><ShieldCheck aria-hidden="true" /></span>
            <span>PHISHING <strong>SHIELD</strong></span>
          </a>
          <div className="story-copy">
            <span className="eyebrow"><span className="eyebrow-dot" /> PERSONAL SECURITY INTELLIGENCE</span>
            <h1>Your digital shield against phishing &amp; online scams.</h1>
            <p>Analyze suspicious URLs and messages with evidence-led security checks and real threat intelligence.</p>
            <div className="story-proof">
              <div className="proof-icon"><Fingerprint aria-hidden="true" /></div>
              <div><strong>Detect. Analyze. Protect.</strong><span>Clear evidence. No invented verdicts.</span></div>
              <ChevronRight className="proof-arrow" aria-hidden="true" />
            </div>
          </div>
          <div className="story-features">
            <div><Link2 aria-hidden="true" /><span>URL protection</span></div>
            <div><MessageSquareText aria-hidden="true" /><span>Message analysis</span></div>
            <div><Globe2 aria-hidden="true" /><span>Threat intelligence</span></div>
          </div>
          <div className="auth-story-footer"><span>PRIVATE BY DESIGN</span><span>ANALYSIS WITH VISIBLE EVIDENCE</span></div>
        </div>
      </section>

      <section className="auth-panel" aria-label="Sign in to Phishing Shield">
        <div className="auth-panel-top"><span>Already protected?</span><button className="text-button" onClick={() => { setMode('signin'); clearFeedback() }}>Sign in</button></div>
        <div className="auth-card">
          <div className="mobile-brand brand-lockup"><span className="brand-mark"><ShieldCheck aria-hidden="true" /></span><span>PHISHING <strong>SHIELD</strong></span></div>
          <span className="eyebrow auth-eyebrow">SECURE ACCESS</span>
          <h2>{heading}</h2>
          <p className="auth-subtitle">{mode === 'signup' ? 'Start protecting your inbox and browsing.' : mode === 'reset' ? 'We’ll email you a secure password reset link.' : 'Sign in to review scans and protect what matters.'}</p>

          {mode !== 'phone' && mode !== 'reset' && (
            <div className="auth-tabs" role="tablist" aria-label="Account action">
              <button role="tab" aria-selected={mode === 'signin'} className={mode === 'signin' ? 'active' : ''} onClick={() => { setMode('signin'); clearFeedback() }}>Sign in</button>
              <button role="tab" aria-selected={mode === 'signup'} className={mode === 'signup' ? 'active' : ''} onClick={() => { setMode('signup'); clearFeedback() }}>Create account</button>
            </div>
          )}

          {mode !== 'phone' && (
            <form className="auth-form" onSubmit={handleEmailAuth}>
              <label htmlFor="auth-email">Email address</label>
              <div className="auth-input-wrap"><Mail aria-hidden="true" /><input id="auth-email" type="email" autoComplete="email" required placeholder="you@company.com" value={email} onChange={(event) => setEmail(event.target.value)} /></div>
              {mode !== 'reset' && <>
                <div className="password-label"><label htmlFor="auth-password">Password</label>{mode === 'signin' && <button type="button" className="text-button" onClick={() => { setMode('reset'); clearFeedback() }}>Forgot password?</button>}</div>
                <div className="auth-input-wrap"><LockKeyhole aria-hidden="true" /><input id="auth-password" type="password" autoComplete={mode === 'signup' ? 'new-password' : 'current-password'} minLength={8} required placeholder="At least 8 characters" value={password} onChange={(event) => setPassword(event.target.value)} /></div>
              </>}
              <button className="primary-button auth-submit" type="submit" disabled={busy}>{busy ? 'Please wait…' : mode === 'signup' ? 'Create account' : mode === 'reset' ? 'Send reset link' : 'Sign in securely'}<ArrowRight aria-hidden="true" /></button>
            </form>
          )}

          {mode === 'phone' && (
            <form className="auth-form" onSubmit={handlePhone}>
              <label htmlFor="auth-phone">Mobile number</label>
              <div className="auth-input-wrap"><Smartphone aria-hidden="true" /><input id="auth-phone" type="tel" autoComplete="tel" required placeholder="+1 555 010 1234" value={phone} onChange={(event) => setPhone(event.target.value)} disabled={otpSent} /></div>
              {otpSent && <><label htmlFor="auth-otp">One-time code</label><div className="auth-input-wrap"><LockKeyhole aria-hidden="true" /><input id="auth-otp" inputMode="numeric" autoComplete="one-time-code" required minLength={4} maxLength={8} placeholder="Enter your code" value={otp} onChange={(event) => setOtp(event.target.value)} /></div></>}
              <button className="primary-button auth-submit" type="submit" disabled={busy}>{busy ? 'Please wait…' : otpSent ? 'Verify code' : 'Send one-time code'}<ArrowRight aria-hidden="true" /></button>
              {otpSent && <button className="text-button centered-action" type="button" onClick={() => { setOtpSent(false); setOtp(''); clearFeedback() }}>Use another number</button>}
            </form>
          )}

          {mode !== 'phone' && mode !== 'reset' && <>
            <div className="auth-divider"><span>OR CONTINUE WITH</span></div>
            <button type="button" className="secondary-button" onClick={handleGoogle} disabled={busy}><span className="google-g" aria-hidden="true">G</span>Continue with Google</button>
            <button type="button" className="secondary-button phone-button" onClick={() => { setMode('phone'); clearFeedback() }} disabled={busy}><Smartphone aria-hidden="true" />Continue with phone</button>
          </>}

          {(mode === 'phone' || mode === 'reset') && <button className="text-button centered-action" type="button" onClick={() => { setMode('signin'); clearFeedback() }}>Back to sign in</button>}
          {error && <p className="auth-feedback error-feedback" role="alert">{error}</p>}
          {notice && <p className="auth-feedback success-feedback" role="status"><Check aria-hidden="true" />{notice}</p>}
          <p className="auth-legal">Your account is protected by Supabase authentication. Scan history is private to your account; message text is never retained.</p>
        </div>
        <div className="auth-panel-footer"><span><span className="footer-shield"><ShieldCheck aria-hidden="true" /></span> Secure, private, evidence-led</span><span>© 2026 PHISHING SHIELD</span></div>
      </section>
    </main>
  )
}
