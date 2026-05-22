import React from 'react';
import { Link } from 'react-router-dom';
import { PageHeader } from '../components/ui';

export const ForgotPassword: React.FC = () => (
  <div className="min-h-screen flex items-center justify-center" style={{ background: 'var(--color-background)' }}>
    <div className="w-full max-w-md">
      <div className="text-center mb-8">
        <div className="w-10 h-10 rounded-lg mx-auto flex items-center justify-center text-sm font-black mb-4" style={{ background: 'var(--color-primary)', color: '#000' }}>VF</div>
        <h1 className="text-2xl font-bold" style={{ color: 'var(--color-text-main)' }}>Reset Password</h1>
        <p className="text-sm mt-1" style={{ color: 'var(--color-text-muted)' }}>Enter your email to receive reset instructions</p>
      </div>
      <div className="card p-6">
        <div className="p-3 rounded mb-4 text-sm" style={{ background: 'rgba(210,153,34,0.1)', border: '1px solid rgba(210,153,34,0.3)', color: 'var(--color-warning)' }}>
          ⚠ In this beta version, password resets are handled by your administrator. Contact your org admin directly.
        </div>
        <form onSubmit={e => e.preventDefault()}>
          <div className="mb-4">
            <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--color-text-muted)' }}>Email Address</label>
            <input type="email" className="input" placeholder="you@company.com" />
          </div>
          <button type="submit" className="btn-primary w-full">Send Reset Email</button>
        </form>
        <div className="text-center mt-4">
          <Link to="/login" className="text-sm" style={{ color: 'var(--color-primary)' }}>← Back to Sign In</Link>
        </div>
      </div>
    </div>
  </div>
);
