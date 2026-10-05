'use client'

import { useState, type FormEvent } from 'react'
import { useRouter } from 'next/navigation'
import { ShieldCheck } from 'lucide-react'
import { createClient } from '@/lib/supabase/client'

export function ResetPasswordForm() {
  const router = useRouter()
  const supabase = createClient()
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    setBusy(true)
    const { error: updateError } = await supabase.auth.updateUser({ password })
    setBusy(false)
    if (updateError) {
      setError(updateError.message.toLowerCase().includes('weak') ? 'Choose a stronger password with at least 8 characters.' : 'The password could not be updated. Request a new reset link and try again.')
      return
    }
    router.replace('/dashboard')
    router.refresh()
  }

  return (
    <main className="reset-page">
      <section className="reset-card">
        <span className="brand-mark"><ShieldCheck aria-hidden="true" /></span>
        <span className="eyebrow">ACCOUNT SECURITY</span>
        <h1>Choose a new password</h1>
        <p>Use a unique password with at least 8 characters.</p>
        <form className="auth-form" onSubmit={submit}>
          <label htmlFor="new-password">New password</label>
          <input className="plain-auth-input" id="new-password" type="password" minLength={8} autoComplete="new-password" required value={password} onChange={(event) => setPassword(event.target.value)} />
          {error && <p className="auth-feedback error-feedback" role="alert">{error}</p>}
          <button className="primary-button auth-submit" disabled={busy}>{busy ? 'Saving…' : 'Update password'}</button>
        </form>
      </section>
    </main>
  )
}
