import jwt from 'jsonwebtoken';

interface User {
    name: string;
    email: string;
    password: string;
  }

const refreshTokens: string[] = [];

export const authenticateToken = async (token: string) => {
  try {
    // Verify the token using the same secret or key used to sign it
    const decodedToken = await jwt.verify(token, process.env.ACCESS_TOKEN_SECRET as string);

    // Token is valid
    return { isValidToken: true, decodedToken };
  } catch (error) {
    // Token is invalid or expired
    console.error(error);
    return "Invalid or expired token";
  }
};

export const generateTokens = async (user: User) => {
  const { password, ...userWithoutPassword } = user;
  

  const accessToken = jwt.sign(userWithoutPassword, process.env.ACCESS_TOKEN_SECRET as string, { expiresIn: '6h' });
  const refreshToken = jwt.sign(userWithoutPassword, process.env.REFRESH_TOKEN_SECRET as string);

  refreshTokens.push(refreshToken);

  return {
    accessToken,
    refreshToken,
  };
};

export const refreshAccessToken = async (refreshToken: string) => {
  try {
    const decodedToken = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET as string);

    if (!refreshTokens.includes(refreshToken)) {
      throw new Error('Invalid refresh token');
    }

    const accessToken = jwt.sign(decodedToken, process.env.ACCESS_TOKEN_SECRET as string, { expiresIn: '6h' });
    return accessToken;
  } catch (error) {
    throw new Error('Invalid refresh token');
  }
};

export const deleteRefresh = async (refreshToken: string) => {
  try {
    const index = refreshTokens.findIndex((token) => token === refreshToken);
    if (index !== -1) {
      refreshTokens.splice(index, 1);
    }
    return 'Logout successful';
  } catch (error) {
    throw new Error('Invalid refresh token');
  }
};
