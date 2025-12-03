// src/routes/auth.routes.js
import { Router } from "express";
import {
  registerUser,
  loginUser,
  refreshAccessToken,
  logoutCurrentDevice,
  logoutAllDevices,
} from "../controllers/auth.controller.js";
import { auth } from "../middleware/auth.middleware.js";
import { authLimiter } from "../middleware/rateLimit.middleware.js";

const router = Router();

// apply authLimiter only on sensitive auth routes
router.post("/register", authLimiter, registerUser);
router.post("/login", authLimiter, loginUser);

router.post("/refresh", refreshAccessToken);
router.post("/logout", logoutCurrentDevice);
router.post("/logout-all", auth, logoutAllDevices);

export default router;
