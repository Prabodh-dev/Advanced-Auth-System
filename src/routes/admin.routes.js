// src/routes/admin.routes.js
import { Router } from "express";
import { auth } from "../middleware/auth.middleware.js";
import { requireRole } from "../middleware/role.middleware.js";
import {
  getAllUsers,
  deactivateUser,
} from "../controllers/admin.controller.js";

const router = Router();

// only admins can access these routes
router.get("/users", auth, requireRole("admin"), getAllUsers);
router.patch(
  "/users/:id/deactivate",
  auth,
  requireRole("admin"),
  deactivateUser
);

export default router;
