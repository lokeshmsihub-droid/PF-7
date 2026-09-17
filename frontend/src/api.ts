import axios from 'axios';

// Create an Axios instance with base configuration
export const api = axios.create({
  baseURL: '/api/compliance',
  headers: {
    'Content-Type': 'application/json',
    // We use a fixed tenant ID for the purpose of this prototype as required by the backend
    'X-Tenant-ID': 'tenant-acme-corp' 
  },
});

// Optionally, add response interceptors for global error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('API Error:', error.response?.data || error.message);
    return Promise.reject(error);
  }
);
