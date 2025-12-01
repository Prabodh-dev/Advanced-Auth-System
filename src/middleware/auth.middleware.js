// src/middleware/auth.middleware.js
import { ApiError } from "../utils/ApiError.js";
import { verifyAccessToken } from "../utils/jwt.js";
import { User } from "../models/user.model.js";

export const auth = async (req, res, next) => {
  try {
    const token = req.cookies?.accessToken;

    if (!token) {
      throw new ApiError(401, "Not authenticated");
    }

    let decoded;
    try {
      decoded = verifyAccessToken(token); // verify JWT
    } catch (err) {
      throw new ApiError(401, "Invalid or expired access token");
    }

    // Find user from DB
    const user = await User.findById(decoded.sub).select(
      "-password -refreshTokens"
    );

    if (!user) {
      throw new ApiError(401, "User no longer exists");
    }

    // Attach to req
    req.user = user;

    next();
  } catch (err) {
    next(err);
  }
};
