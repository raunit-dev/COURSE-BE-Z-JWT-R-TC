const { Router } = require("express");
const adminRouter = Router();
const { adminModel, courseModel } = require("../db");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const zod = require("zod");
const { JWT_ADMIN_PASSWORD } = require("../config");
const { adminMiddleware } = require("../middleware/admin");

const signupSchema = zod.object({
    email: zod.string().email(),
    password: zod.string().min(8).refine(
        (password) => {
            const hasUppercase = /[A-Z]/.test(password);
            const hasLowercase = /[a-z]/.test(password);
            const hasNumber = /[0-9]/.test(password);
            const hasSpecialChar = /[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]/.test(password);

            return hasUppercase && hasLowercase && hasNumber && hasSpecialChar;
        },
        {
            message:
                "Password must contain at least 8 characters, one uppercase, one lowercase, one number, and one special character",
        }
    ),
    firstName: zod.string(),
    lastName: zod.string(),
});

adminRouter.post("/signup", async function (req, res) {
    try {
        const { success } = signupSchema.safeParse(req.body);

        if (!success) {
            return res.status(400).json({ message: "Incorrect inputs" });
        }

        const { email, password, firstName, lastName } = req.body;

        const existingAdmin = await adminModel.findOne({ email });
        if (existingAdmin) {
            return res.status(400).json({ message: "Admin with this email already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newAdmin = await adminModel.create({
            email,
            password: hashedPassword,
            firstName,
            lastName,
        });

        const token = jwt.sign({ id: newAdmin._id }, JWT_ADMIN_PASSWORD);

        res.json({ message: "Signup succeeded", token });
    } catch (error) {
        console.error("Signup error:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

adminRouter.post("/signin", async function (req, res) {
    try {
        const { email, password } = req.body;

        const admin = await adminModel.findOne({ email });

        if (!admin) {
            return res.status(403).json({ message: "Incorrect credentials" });
        }

        const passwordMatch = await bcrypt.compare(password, admin.password);
        if (!passwordMatch) {
            return res.status(403).json({ message: "Incorrect credentials" });
        }

        const token = jwt.sign({ id: admin._id }, JWT_ADMIN_PASSWORD);
        res.json({ token });
    } catch (error) {
        console.error("Signin error:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

const courseSchema = zod.object({
    title: zod.string(),
    description: zod.string(),
    imageUrl: zod.string().url(),
    price: zod.number(),
});

adminRouter.post("/course", adminMiddleware, async function (req, res) {
    try {
        const adminId = req.userId;
        const { success } = courseSchema.safeParse(req.body);

        if (!success) {
            return res.status(400).json({ message: "Incorrect inputs" });
        }

        const { title, description, imageUrl, price } = req.body;

        const course = await courseModel.create({
            title,
            description,
            imageUrl,
            price,
            creatorId: adminId,
        });

        res.json({ message: "Course created", courseId: course._id });
    } catch (error) {
        console.error("Create course error:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

adminRouter.put("/course", adminMiddleware, async function (req, res) {
    try {
        const adminId = req.userId;
        const { courseId, ...updates } = req.body;

        const course = await courseModel.findOneAndUpdate(
            { _id: courseId, creatorId: adminId },
            updates,
            { new: true }
        );

        if (!course) {
            return res.status(404).json({ message: "Course not found" });
        }

        res.json({ message: "Course updated successfully", course });
    } catch (error) {
        console.error("Update course error:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

adminRouter.get("/course/bulk", adminMiddleware, async function (req, res) {
    try {
        const adminId = req.userId;

        const courses = await courseModel.find({ creatorId: adminId });

        res.json({ courses });
    } catch (error) {
        console.error("Get bulk courses error:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

module.exports = {
    adminRouter: adminRouter,
};
