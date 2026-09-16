import axios from 'axios';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export const api = axios.create({
  baseURL: API_BASE_URL,
});

export async function getAuthToken(): Promise<string> {
  if (typeof window === 'undefined') return '';
  
  let token = localStorage.getItem('yarox_token');
  if (token) return token;

  // Auto-authenticate with default analyst credentials in dev environment
  try {
    const res = await axios.post(`${API_BASE_URL}/auth/login`, {
      email: 'analyst@yarox.local',
      password: 'YaroxAnalyst2026!'
    });
    if (res.data && res.data.access_token) {
      token = res.data.access_token;
      localStorage.setItem('yarox_token', token);
      return token;
    }
  } catch (err) {
    console.warn('Auto-login for frontend failed:', err);
  }
  return '';
}

// Request interceptor to attach JWT token
api.interceptors.request.use(async (config) => {
  const token = await getAuthToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
}, (error) => Promise.reject(error));

/**
 * Downloads the PDF rendered from the case's current persisted report.
 * Uses the authenticated API client (window.open cannot send the bearer token).
 */
export async function downloadReportPdf(caseId: string): Promise<void> {
  const res = await api.get(`/investigations/${caseId}/export`, { responseType: 'blob' });
  const url = URL.createObjectURL(res.data);
  const link = document.createElement('a');
  link.href = url;
  const disposition: string = res.headers['content-disposition'] || '';
  const match = disposition.match(/filename=([^;]+)/);
  link.download = match ? match[1] : `SOC_Report_${caseId}.pdf`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

// Response interceptor to re-authenticate on 401
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response && error.response.status === 401 && typeof window !== 'undefined') {
      localStorage.removeItem('yarox_token');
      const token = await getAuthToken();
      if (token && error.config) {
        error.config.headers.Authorization = `Bearer ${token}`;
        return axios(error.config);
      }
    }
    return Promise.reject(error);
  }
);
