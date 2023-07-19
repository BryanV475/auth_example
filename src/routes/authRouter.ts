import express, { Router, Request, Response } from 'express';
import { generateTokens, refreshAccessToken, authenticateToken, deleteRefresh } from '../controllers/auth';
import bcrypt from 'bcrypt';

const authRouter: Router = express.Router();

interface User {
  name: string;
  email: string;
  password: string;
}

const users: User[] = [];

authRouter.post('/register', async (req: Request, res: Response) => {
  try {
    const { name, email, password } = req.body;

    // Check if user with the same email already exists
    const existingUser = users.find((user) => user.email === email);
    if (existingUser) {
      return res.status(409).json({ message: 'User with the same email already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser: User = {
      name,
      email,
      password: hashedPassword,
    };

    users.push(newUser);

    // Generate tokens
    const tokens = await generateTokens(newUser);

    res.json(tokens);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Login route
authRouter.post('/login', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    const foundUser = users.find((user) => user.email === email);
    if (!foundUser) {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    const passwordMatch = await bcrypt.compare(password, foundUser.password);
    if (!passwordMatch) {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    const tokens = await generateTokens(foundUser);
    res.json(tokens);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Verify token route
authRouter.get('/verify', async (req: Request, res: Response) => {
  const authHeader = req.headers['authorization'];

  if (!authHeader) {
    return res.status(401).json({ message: 'No authorization header provided' });
  }

  const token = authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const isValidToken = await authenticateToken(token);
    return res.json(isValidToken);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

// Refresh token route
authRouter.post('/refresh', async (req: Request, res: Response) => {
  const { refreshToken } = req.body;

  try {
    const accessToken = await refreshAccessToken(refreshToken);
    res.json({ accessToken });
  } catch (error) {
    res.status(403).json({ message: 'Failed to refresh access token' });
  }
});

// logout route
authRouter.post('/logout', async (req: Request, res: Response) => {
    const { refreshToken } = req.body;
  
    try {
      await deleteRefresh(refreshToken)
      res.json({ message: 'Logout successfull'});
    } catch (error) {
      res.status(403).json({ message: 'Failed' });
    }
  });
  

export default authRouter;
