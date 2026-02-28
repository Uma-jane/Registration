import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from '../api/axios';

function Dashboard() {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const navigate = useNavigate();

    useEffect(() => {
        const checkAuth = async () => {
            try {
                const response = await axios.get('/verify-auth');
                setUser(response.data.user);
            } catch (err) {
                navigate('/login');
            } finally {
                setLoading(false);
            }
        };

        checkAuth();
    }, [navigate]);

    const handleLogout = async () => {
        try {
            await axios.post('/logout');
            navigate('/login');
        } catch (err) {
            console.error('Logout failed', err);
        }
    };

    if (loading) {
        return <div style={{ color: 'white' }}>Loading...</div>;
    }

    return (
        <div className="dashboard-container">
            <h1 className="dashboard-title">Hello Welcome</h1>
            <p className="dashboard-user">Logged in as {user?.username}</p>
            <button onClick={handleLogout} className="logout-btn">
                Logout
            </button>
        </div>
    );
}

export default Dashboard;
