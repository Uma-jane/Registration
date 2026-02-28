import axios from 'axios';

const instance = axios.create({
    baseURL: 'http://localhost:5000',
    withCredentials: true // Important for cookies!
});

export default instance;
