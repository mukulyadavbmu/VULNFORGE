import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { register } from '../api';

export const Register = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      await register(email, password, name);
      // Auto-redirect to login after successful registration
      navigate('/login');
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <div className="panel w-full max-w-md p-8 shadow-xl">
        <h2 className="text-2xl font-bold mb-6 text-center text-primary">Join VulnForge</h2>
        {error && <div className="message border-danger text-danger bg-danger/10">{error}</div>}
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div>
            <label className="text-sm text-textMuted mb-1 block">Name</label>
            <input
              type="text"
              value={name}
              onChange={e => setName(e.target.value)}
              className="w-full bg-surface border border-border rounded p-2 text-textMain focus:border-primary focus:outline-none"
              required
            />
          </div>
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
          <button 
            type="submit" 
            disabled={loading}
            className="bg-primary text-background font-bold py-2 rounded hover:opacity-90 mt-2 transition-opacity disabled:opacity-50"
          >
            {loading ? 'Creating Account...' : 'Register'}
          </button>
        </form>
        <p className="mt-4 text-center text-sm text-textMuted">
          Already have an account? <Link to="/login" className="text-primary hover:underline">Log in</Link>
        </p>
      </div>
    </div>
  );
};
