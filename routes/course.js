const { Router } = require("express");
const { userMiddleware } = require("../middleware/user");
const { purchaseModel, courseModel } = require("../db")
const courseRouter = Router();

courseRouter.post("/purchase", userMiddleware, async function(req, res) {
    const userId = req.userId;
    const courseId = req.body.courseId;

    const course = await courseModel.findById(courseId);

    if (!course) {
        return res.status(404).json({ message: "Course not found" });
    }


    await purchaseModel.create({
        userId,
        courseId
    })

    res.json({
        message: "You have successfully bought the course"
    })
})

courseRouter.get("/preview", async function(req, res) {
    
    const courses = await courseModel.find({});

    res.json({
        courses
    })
})

module.exports = {
    courseRouter: courseRouter
}