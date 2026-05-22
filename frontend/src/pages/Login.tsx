import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { login } from '../api';
import { useAuth } from '../contexts/AuthContext';

export const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const { login: authLogin } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await login(email, password);
      authLogin(res.token, res.user);
      navigate('/');
    } catch (err: any) {
      setError(err.message);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <div className="panel w-full max-w-md p-8 shadow-xl">
        <h2 className="text-2xl font-bold mb-6 text-center text-primary">VulnForge</h2>
        {error && <div className="message border-danger text-danger bg-danger/10">{error}</div>}
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div>
            <label className="text-sm text-textMuted mb-1 block">Email</label>
            <input
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              className="w-full bg-surface border border-border rounded p-2 text-textMain focus:border-primary focus:outline-none"
              required
            />
          </div>
          <div>
            <label className="text-sm text-textMuted mb-1 block">Password</label>
            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              className="w-full bg-surface border border-border rounded p-2 text-textMain focus:border-primary focus:outline-none"
              required
            />
          </div>
          <button type="submit" className="bg-primary text-background font-bold py-2 rounded hover:opacity-90 mt-2 transition-opacity">
            Sign In
          </button>
        </form>
        <p className="mt-4 text-center text-sm text-textMuted">
          Don't have an account? <Link to="/register" className="text-primary hover:underline">Register</Link>
        </p>
      </div>
    </div>
  );
};
