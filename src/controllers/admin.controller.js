// src/controllers/admin.controller.js
import { User } from "../models/user.model.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";

// GET /api/admin/users  -> list all users (basic info only)
export const getAllUsers = asyncHandler(async (req, res) => {
  const users = await User.find({}).select(
    "name email role isActive lastLoginAt createdAt"
  );

  return res
    .status(200)
    .json(new ApiResponse(200, { users }, "Fetched all users"));
});

// PATCH /api/admin/users/:id/deactivate  -> deactivate user
export const deactivateUser = asyncHandler(async (req, res) => {
  const { id } = req.params;

  const user = await User.findById(id);

  if (!user) {
    throw new ApiError(404, "User not found");
  }

  if (user.role === "admin") {
    throw new ApiError(400, "Cannot deactivate another admin");
  }

  user.isActive = false;
  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, { userId: user._id }, "User deactivated"));
});
