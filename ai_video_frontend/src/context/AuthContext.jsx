import { createContext, useState, useEffect } from "react";
import axios from "axios";

const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [accessToken, setAccessToken] = useState(null);

  useEffect(() => {
    refreshToken();
  }, []);

  const login = async (username, password) => {
    try {
      const response = await axios.post("http://localhost:8000/login", 
        new URLSearchParams({ username, password }),
        { withCredentials: true }
      );
      setAccessToken(response.data.access_token);
      setUser(username);
    } catch (error) {
      console.error("Login failed", error);
    }
  };

  const refreshToken = async () => {
    try {
      const response = await axios.post("http://localhost:8000/refresh-token", {}, { withCredentials: true });
      setAccessToken(response.data.access_token);
    } catch (error) {
      console.error("Failed to refresh token", error);
    }
  };

  const logout = () => {
    setUser(null);
    setAccessToken(null);
    // Ideally, also make an API request to invalidate refresh token in DB
  };

  return (
    <AuthContext.Provider value={{ user, accessToken, login, logout, refreshToken }}>
      {children}
    </AuthContext.Provider>
  );
}

export default AuthContext;
