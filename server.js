const express = require("express");
const path = require("path");
const fs = require("fs");
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());
app.use(cors());

const COURSES_FILE = path.join(__dirname, "savedCourses.json");

let courses = [
    { id: 1, name: "Mathematics", description: "Covers algebra, calculus, and statistics." },
    { id: 2, name: "Science", description: "Covers physics, chemistry, and biology." },
    { id: 3, name: "History", description: "Covers world history and modern history." },
    { id: 4, name: "Literature", description: "Covers poetry, drama, and classical literature." },
    { id: 5, name: "Computer Science", description: "Covers programming and data structures." }
];

// Serve HTML pages
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/about", (req, res) => res.sendFile(path.join(__dirname, "public", "about.html")));
app.get("/courses", (req, res) => res.sendFile(path.join(__dirname, "public", "courses.html")));

// API to get all courses
app.get("/api/courses", (req, res) => res.json(courses));

// API to get a specific course
app.get("/api/courses/:id", (req, res) => {
    const course = courses.find(c => c.id === parseInt(req.params.id));
    if (course) res.json(course);
    else res.status(404).json({ message: "Course not found" });
});

// Function to read saved courses
function readSavedCourses() {
    if (!fs.existsSync(COURSES_FILE)) return [];
    return JSON.parse(fs.readFileSync(COURSES_FILE, "utf-8") || "[]");
}

// Function to write saved courses
function writeSavedCourses(courses) {
    fs.writeFileSync(COURSES_FILE, JSON.stringify(courses, null, 2));
}

// API to add a course to savedCourses.json
app.post("/api/save-course", (req, res) => {
    const course = { id: Date.now(), ...req.body };
    let savedCourses = readSavedCourses();
    savedCourses.push(course);
    writeSavedCourses(savedCourses);
    res.json({ message: "Course saved successfully", course });
});

// API to retrieve saved courses
app.get("/api/saved-courses", (req, res) => {
    res.json(readSavedCourses());
});

// API to remove a course from savedCourses.json
app.delete("/api/remove-course/:id", (req, res) => {
    let savedCourses = readSavedCourses();
    const courseId = parseInt(req.params.id);
    savedCourses = savedCourses.filter(course => course.id !== courseId);
    writeSavedCourses(savedCourses);
    res.json({ message: "Course removed successfully" });
});

app.post("/api/add-course", (req, res) => {
    const { name, description } = req.body;

    // Ensure course name and description are provided
    if (!name || !description) {
        return res.status(400).json({ message: "Name and description are required" });
    }

    // Create a new course object
    const newCourse = {
        id: courses.length + 1,  // Create a new unique ID for the course
        name,
        description
    };

    // Add the new course to the array
    courses.push(newCourse);

    // Respond with the newly added course
    res.status(201).json(newCourse);
});

// DELETE route to remove a course
app.delete("/api/courses/:id", (req, res) => {
    const { id } = req.params;
    const index = courses.findIndex(course => course.id === parseInt(id));

    if (index === -1) {
        return res.status(404).json({ message: "Course not found" });
    }

    // Remove the course from the array
    courses.splice(index, 1);
    res.status(200).json({ message: "Course deleted successfully" });
});


// Start server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
