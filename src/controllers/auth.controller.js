// src/controllers/auth.controller.js
import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
} from "../utils/jwt.js";

const loginAttempts = new Map();

const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_TIME_MS = 15 * 60 * 1000;

const ACCESS_COOKIE_OPTIONS = {
  httpOnly: true,
  sameSite: "lax",
  secure: process.env.NODE_ENV === "production",
};

const REFRESH_COOKIE_OPTIONS = {
  httpOnly: true,
  sameSite: "lax",
  secure: process.env.NODE_ENV === "production",
};

const setAuthCookies = (res, accessToken, refreshToken) => {
  res.cookie("accessToken", accessToken, {
    ...ACCESS_COOKIE_OPTIONS,
    maxAge: 15 * 60 * 1000, // 15 minutes
  });

  res.cookie("refreshToken", refreshToken, {
    ...REFRESH_COOKIE_OPTIONS,
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });
};

const clearAuthCookies = (res) => {
  res.clearCookie("accessToken", ACCESS_COOKIE_OPTIONS);
  res.clearCookie("refreshToken", REFRESH_COOKIE_OPTIONS);
};

const getClientMeta = (req) => {
  const userAgent = req.headers["user-agent"] || "unknown";
  const forwarded = req.headers["x-forwarded-for"];
  const ip = Array.isArray(forwarded)
    ? forwarded[0]
    : forwarded?.split(",")[0] || req.ip || "unknown";

  return { userAgent, ip };
};

// POST /api/auth/register
export const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    throw new ApiError(400, "Name, email and password are required");
  }

  const existingUser = await User.findOne({ email });

  if (existingUser) {
    throw new ApiError(409, "User with this email already exists");
  }

  const user = await User.create({
    name,
    email,
    password,
  });

  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  const { userAgent, ip } = getClientMeta(req);
  const refreshExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  user.refreshTokens.push({
    token: refreshToken,
    userAgent,
    ip,
    expiresAt: refreshExpiresAt,
  });

  await user.save({ validateBeforeSave: false });

  user.password = undefined;

  setAuthCookies(res, accessToken, refreshToken);

  return res
    .status(201)
    .json(new ApiResponse(201, { user }, "User registered successfully"));
});

// POST /api/auth/login
export const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    throw new ApiError(400, "Email and password are required");
  }

  // ---- Brute-force protection (per email) ----
  const now = Date.now();
  const entry = loginAttempts.get(email);

  if (entry?.lockedUntil && entry.lockedUntil > now) {
    const waitSeconds = Math.ceil((entry.lockedUntil - now) / 1000);
    throw new ApiError(
      429,
      `Too many failed attempts. Try again after ${waitSeconds} seconds`
    );
  }

  const user = await User.findOne({ email }).select("+password +refreshTokens");

  if (!user) {
    // Increment failed attempts even if user doesn't exist (avoid user enumeration)
    const prev = loginAttempts.get(email) || { attempts: 0, lastAttempt: now };
    const attempts = prev.attempts + 1;
    let lockedUntil = prev.lockedUntil;

    if (attempts >= MAX_LOGIN_ATTEMPTS) {
      lockedUntil = now + LOCK_TIME_MS;
    }

    loginAttempts.set(email, { attempts, lastAttempt: now, lockedUntil });

    throw new ApiError(401, "Invalid email or password");
  }

  const isPasswordValid = await user.comparePassword(password);

  if (!isPasswordValid) {
    const prev = loginAttempts.get(email) || { attempts: 0, lastAttempt: now };
    const attempts = prev.attempts + 1;
    let lockedUntil = prev.lockedUntil;

    if (attempts >= MAX_LOGIN_ATTEMPTS) {
      lockedUntil = now + LOCK_TIME_MS;
    }

    loginAttempts.set(email, { attempts, lastAttempt: now, lockedUntil });

    throw new ApiError(401, "Invalid email or password");
  }

  // Login success → reset failed attempts for this email
  loginAttempts.delete(email);

  if (!user.isActive) {
    throw new ApiError(403, "User account is inactive");
  }

  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  const { userAgent, ip } = getClientMeta(req);
  const refreshExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  user.refreshTokens.push({
    token: refreshToken,
    userAgent,
    ip,
    expiresAt: refreshExpiresAt,
  });

  user.lastLoginAt = new Date();

  await user.save({ validateBeforeSave: false });

  user.password = undefined;

  setAuthCookies(res, accessToken, refreshToken);

  return res
    .status(200)
    .json(new ApiResponse(200, { user }, "Logged in successfully"));
});

// POST /api/auth/refresh
export const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken =
    req.cookies?.refreshToken || req.body?.refreshToken;

  if (!incomingRefreshToken) {
    throw new ApiError(401, "Refresh token missing");
  }

  let decoded;
  try {
    decoded = verifyRefreshToken(incomingRefreshToken);
  } catch (err) {
    throw new ApiError(401, "Invalid or expired refresh token");
  }

  const user = await User.findById(decoded.sub).select("+refreshTokens");

  if (!user) {
    throw new ApiError(401, "User not found");
  }

  // Find matching refresh session
  const existingTokenEntry = user.refreshTokens.find(
    (t) => t.token === incomingRefreshToken
  );

  if (!existingTokenEntry) {
    throw new ApiError(401, "Refresh session not found (maybe logged out)");
  }

  if (existingTokenEntry.expiresAt < new Date()) {
    throw new ApiError(401, "Refresh token expired");
  }

  // Rotate refresh token for better security
  const newAccessToken = generateAccessToken(user);
  const newRefreshToken = generateRefreshToken(user);

  const { userAgent, ip } = getClientMeta(req);
  const refreshExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  // Remove old token and add new one
  user.refreshTokens = user.refreshTokens.filter(
    (t) => t.token !== incomingRefreshToken
  );
  user.refreshTokens.push({
    token: newRefreshToken,
    userAgent,
    ip,
    expiresAt: refreshExpiresAt,
  });

  await user.save({ validateBeforeSave: false });

  setAuthCookies(res, newAccessToken, newRefreshToken);

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        { user: { id: user._id, email: user.email } },
        "Token refreshed"
      )
    );
});

// POST /api/auth/logout (this device only)
export const logoutCurrentDevice = asyncHandler(async (req, res) => {
  const incomingRefreshToken =
    req.cookies?.refreshToken || req.body?.refreshToken;

  if (!incomingRefreshToken) {
    clearAuthCookies(res);
    return res
      .status(200)
      .json(
        new ApiResponse(200, null, "Logged out (no refresh token present)")
      );
  }

  let decoded;
  try {
    decoded = verifyRefreshToken(incomingRefreshToken);
  } catch (err) {
    // Even if invalid, clear cookies
    clearAuthCookies(res);
    return res
      .status(200)
      .json(new ApiResponse(200, null, "Logged out (invalid token cleared)"));
  }

  const user = await User.findById(decoded.sub).select("+refreshTokens");

  if (user) {
    user.refreshTokens = user.refreshTokens.filter(
      (t) => t.token !== incomingRefreshToken
    );
    await user.save({ validateBeforeSave: false });
  }

  clearAuthCookies(res);

  return res
    .status(200)
    .json(new ApiResponse(200, null, "Logged out from this device"));
});

// POST /api/auth/logout-all (all devices)
export const logoutAllDevices = asyncHandler(async (req, res) => {
  const userId = req.user?._id;

  if (!userId) {
    throw new ApiError(401, "Not authenticated");
  }

  await User.findByIdAndUpdate(
    userId,
    { $set: { refreshTokens: [] } },
    { new: true }
  );

  clearAuthCookies(res);

  return res
    .status(200)
    .json(new ApiResponse(200, null, "Logged out from all devices"));
});
