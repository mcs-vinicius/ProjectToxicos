import React, { useState, useEffect } from "react";
import { Routes, Route, Link, Navigate, useLocation } from "react-router-dom";
import axios from "axios";

// Pages & Components
import HomePage from "./page/Home.jsx";
import LoginPage from "./components/auth/LoginPage.jsx";
import RegisterUserPage from "./components/auth/RegisterUserPage.jsx";
import RegisterMemberPage from "./components/ranking/RegisterPage.jsx";
import ResultsPage from "./components/ranking/ResultsPage.jsx";
import UserManagementPage from "./page/UserManagementPage.jsx"; // Nova Tela
import ProfilePage from "./page/ProfilePage.jsx"; // Nova Tela

// CSS
import "./App.css";

// Configure axios to send cookies with every request
axios.defaults.withCredentials = true;

const apiUrl = import.meta.env.VITE_API_URL;
const App = () => {
  const [auth, setAuth] = useState({
    isLoggedIn: false,
    user: null,
    loading: true,
  });

  const location = useLocation();
  

  const checkSession = async () => {
    try {
      const apiUrl = import.meta.env.VITE_API_URL;
      const response = await axios.get(`${apiUrl}/session`);
      if (response.data.isLoggedIn) {
        setAuth({ isLoggedIn: true, user: response.data.user, loading: false });
      } else {
        setAuth({ isLoggedIn: false, user: null, loading: false });
      }
    } catch (error) {
      console.error("Session check failed:", error);
      setAuth({ isLoggedIn: false, user: null, loading: false });
    }
  };

  useEffect(() => {
    checkSession();
  }, []);
  
  const handleLogin = (userData) => {
    setAuth({ isLoggedIn: true, user: userData, loading: false });
  };

  const handleLogout = async () => {
    try {
      await axios.post(`${apiUrl}/logout`);
      setAuth({ isLoggedIn: false, user: null, loading: false });
    } catch (error) {
      console.error("Logout failed:", error);
    }
  };

  // Protective Route Component
  const ProtectedRoute = ({ children, roles }) => {
    if (auth.loading) {
      return <div>Verificando acesso...</div>; // Ou um componente de loader
    }
    if (!auth.isLoggedIn) {
      return <Navigate to="/login" state={{ from: location }} replace />;
    }
    if (roles && !roles.includes(auth.user.role)) {
       return <Navigate to="/" replace />; // Redireciona para home se não tiver permissão
    }
    return children;
  };
  
  if (auth.loading) {
    return <div>Carregando...</div>;
  }

  return (
    <>
      <div className="navsup">
        <Link to="/" className="btt-menu" style={{ marginRight: "15px" }}>Home</Link>
        <Link to="/results" className="btt-menu" style={{ marginRight: "15px" }}>Ranking</Link>
        
        {auth.isLoggedIn && (
          <Link to={`/profile/${auth.user.habby_id}`} className="btt-menu" style={{ marginRight: "15px" }}>
            Meu Perfil
          </Link>
        )}
        
        {auth.isLoggedIn && ['admin', 'leader'].includes(auth.user.role) && (
          <>
            <Link to="/register-member" className="btt-menu" style={{ marginRight: "15px" }}>
               Temporada
            </Link>
            <Link to="/user-management" className="btt-menu" style={{ marginRight: "15px" }}>
              Gerenciar Usuários
            </Link>
          </>
        )}

        <div style={{ marginLeft: "auto" }}>
          {auth.isLoggedIn ? (
            <button onClick={handleLogout} className="btt-menu btt-logout">Sair</button>
          ) : (
            <Link to="/login" className="btt-menu">Login</Link>
          )}
        </div>
      </div>
      
      <div className="content-area">
        <Routes>
          {/* Rotas Públicas */}
          <Route path="/" element={<HomePage userRole={auth.user?.role} />} />
          <Route path="/results" element={<ResultsPage />} />
          <Route path="/login" element={<LoginPage onLogin={handleLogin} />} />
          <Route path="/register-user" element={<RegisterUserPage />} />

          {/* Rotas Protegidas */}
          <Route path="/register-member" element={
            <ProtectedRoute roles={['admin', 'leader']}>
              <RegisterMemberPage />
            </ProtectedRoute>
          } />
          <Route path="/user-management" element={
             <ProtectedRoute roles={['admin', 'leader']}>
              <UserManagementPage currentUser={auth.user} />
            </ProtectedRoute>
          } />
           <Route path="/profile/:habby_id" element={
            <ProtectedRoute roles={['admin', 'leader', 'member']}>
              <ProfilePage currentUser={auth.user}/>
            </ProtectedRoute>
          } />

          {/* Rota de Fallback */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
    </>
  );
};

export default App;

