import axios from 'axios';

const instance = axios.create({
    baseURL: import.meta.env.VITE_API_URL || '',
    withCredentials: true // Important for cookies!
});

export default instance;
