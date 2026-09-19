import axios from 'axios';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

/**
 * Authenticated API client. The session is an httpOnly cookie set by the backend on
 * login (see /auth/login); withCredentials makes the browser send it automatically.
 * No token is ever stored in localStorage or held in JavaScript.
 */
export const api = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true,
});

/**
 * Downloads the PDF rendered from the case's current persisted report.
 * Uses the authenticated API client (window.open cannot send the session cookie
 * across a direct navigation the way a same-origin credentialed request can).
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
