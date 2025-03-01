const express = require("express");
const path = require("path");
const fs = require("fs");
const cors = require("cors");
const bcrypt = require("bcrypt"); 
const app = express();
const jwt = require('jsonwebtoken');

const PORT = process.env.PORT || 5000;
const COURSES_FILE = path.join(__dirname, "courses.json");
const SAVED_COURSES_FILE = path.join(__dirname, "savedCourses.json");
const USERS_FILE = path.join(__dirname, "users.json");
const SECRET_KEY = 'your_secret_key';

app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());
app.use(cors({ origin: 'http://localhost:5000' }));

// Read courses from the file when the server starts
let courses = readCourses();

function writeCourses(courses) {
    try {
        fs.writeFileSync(COURSES_FILE, JSON.stringify(courses, null, 2));
    } catch (error) {
        console.error("Error writing courses file:", error);
    }
}

function readCourses() {
    if (!fs.existsSync(COURSES_FILE)) {
        return [];  // Return empty array if the file doesn't exist
    }
    try {
        return JSON.parse(fs.readFileSync(COURSES_FILE, "utf-8")) || [];
    } catch (error) {
        console.error("Error reading courses file:", error);
        return [];
    }
}

// Serve HTML pages
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/about", (req, res) => res.sendFile(path.join(__dirname, "public", "about.html")));
app.get("/courses", (req, res) => res.sendFile(path.join(__dirname, "public", "courses.html")));
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));


// API to get all courses
app.get("/api/courses", (req, res) => {
    courses = readCourses();
    console.log("Courses requested:", courses);
    res.json(courses);
});

// API to get a specific course
app.get("/api/courses/:id", (req, res) => {
    const courses = readCourses();
    const course = courses.find(c => c.id === parseInt(req.params.id));
    if (course) res.json(course);
    else res.status(404).json({ message: "Course not found" });
});

// API to add a new course
app.post("/api/add-course", verifyTeacherRole, verifyLogin,(req, res) => {
    const { name, description } = req.body;

    if (!name || !description) {
        return res.status(400).json({ message: "Course name and description are required" });
    }

    courses = readCourses(); // Read latest courses
    const newCourse = {
        id: courses.length > 0 ? courses[courses.length - 1].id + 1 : 1, // Auto-increment ID
        name,
        description
    };

    courses.push(newCourse);
    writeCourses(courses); // Save to file

    res.status(201).json({ message: "Course added successfully", course: newCourse });
});


// API to delete a course
app.delete("/api/courses/:id", verifyTeacherRole,verifyLogin, (req, res) => {
    const courseId = parseInt(req.params.id);
    courses = readCourses(); // Read latest courses

    const courseIndex = courses.findIndex(course => course.id === courseId);
    if (courseIndex === -1) {
        return res.status(404).json({ message: "Course not found" });
    }

    courses.splice(courseIndex, 1);  // Remove course from array
    writeCourses(courses);  // Save updated list to file

    res.json({ message: "Course deleted successfully" });
});




//*FOR THE SAVED COURSES SECTION*

// Read saved courses from the file
function readSavedCourses() {
    if (!fs.existsSync(SAVED_COURSES_FILE)) {
        console.error(`File not found: ${SAVED_COURSES_FILE}`);
        return [];
    }
    try {
        const data = fs.readFileSync(SAVED_COURSES_FILE, "utf-8");
        console.log("Read saved courses:", data);  // Log the raw file contents
        return JSON.parse(data) || [];
    } catch (error) {
        console.error("Error reading saved courses file:", error);
        return [];
    }
}

// Write saved courses to savedCourses.json
function writeSavedCourses(courses) {
    try {
        fs.writeFileSync(SAVED_COURSES_FILE, JSON.stringify(courses, null, 2));  // Write to savedCourses.json
    } catch (error) {
        console.error("Error writing saved courses file:", error);
    }
}

// API to add a course to savedCourses.json
app.post("/api/save-course", (req, res) => {
    const newCourse = { id: Date.now(), ...req.body };  // Create a new course with a unique id
    let savedCourses = readSavedCourses();  // Get current saved courses
    savedCourses.push(newCourse);  // Add the new course to the list
    writeSavedCourses(savedCourses);  // Write updated list to savedCourses.json
    res.json({ message: "Course saved successfully", course: newCourse });
});

// API to get all saved courses
app.get("/api/saved-courses", (req, res) => {
    const savedCourses = readSavedCourses();
    console.log('Saved courses:', savedCourses);  // Log saved courses to check
    res.json(savedCourses);
});

// API to delete a saved course
app.delete("/api/remove-course/:id", (req, res) => {
    const courseId = parseInt(req.params.id);  // Get course ID from the URL
    let savedCourses = readSavedCourses();  // Read the saved courses from the file
    savedCourses = savedCourses.filter(course => course.id !== courseId);  // Remove the course with matching ID
    writeSavedCourses(savedCourses);  // Write the updated list back to the file
    res.json({ message: "Course removed from saved courses successfully" });  // Send success message
});




//*LOGIN SECTION
// Helper functions to read and write user data to the file
function readUsersFromFile() {
    try {
        if (fs.existsSync(USERS_FILE)) {
            const data = fs.readFileSync(USERS_FILE, 'utf-8');
            return JSON.parse(data);
        } else {
            return []; // Return an empty array if the file doesn't exist
        }
    } catch (error) {
        console.error("Error reading users file:", error);
        return [];
    }
}

function writeUsersToFile(users) {
    try {
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    } catch (error) {
        console.error("Error writing users file:", error);
    }
}

// API endpoint for user registration
app.post("/api/register", async (req, res) => {
    const { username, password, role } = req.body;

    if (!username || !password || !role) {
        return res
            .status(400)
            .json({ message: "Username, password, and role are required" });
    }

    let users = readUsersFromFile();  // Read users from file

    // Check if username already exists
    if (users.find((user) => user.username === username)) {
        return res.status(400).json({ message: "Username already exists" });
    }

    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);  // 10 is the saltRounds

        const newUser = {
            id: Date.now(),  // Temporary ID
            username,
            password: hashedPassword,
            role,
        };

        users.push(newUser);
        writeUsersToFile(users); // Write the updated users array to the file
        console.log("New user registered:", newUser); // Log the new user

        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        console.error("Error registering user:", error);
        res.status(500).json({ message: "Failed to register user" });
    }
});

// API endpoint for user login
app.post("/api/login", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: "Username and password are required" });
    }

    const users = readUsersFromFile();  // Read users from file
    const user = users.find((user) => user.username === username);

    if (!user) {
        return res.status(401).json({ message: "Invalid credentials" });
    }

    try {
        // Compare password with the hashed password
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (passwordMatch) {
            // Generate JWT token containing user ID and role
            const token = jwt.sign({ userId: user.id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });

            // Send the token to the frontend (e.g., store it in localStorage or cookies)
            res.json({ message: "Login successful", token });
        } else {
            return res.status(401).json({ message: "Invalid credentials" });
        }
    } catch (error) {
        console.error("Error logging in:", error);
        res.status(500).json({ message: "Failed to log in" });
    }
});

// API endpoint for user logout
app.post("/api/logout", (req, res) => {
    const userId = req.headers['user-id']; // Or however you're passing the user ID
    if (userId) {
        // Remove the user's id from the loggedInUsers object
        // delete loggedInUsers[userId];
        res.json({ message: "Logout successful" });
    } else {
        res.status(400).json({ message: "No user logged in with that ID" });
    }
});

// Protected API endpoint (example)
app.get("/api/profile", (req, res) => {
    res.json({ message: "Profile information" });
});

function verifyTeacherRole(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1]; // Extract token from Authorization header

    if (!token) {
        return res.status(401).json({ message: "No token provided" });
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY); // Verify the token

        if (decoded.role !== 'teacher') {
            return res.status(403).json({ message: "Access denied. Only teachers can access this route." });
        }

        req.user = decoded; // Add user data to request
        next(); // Proceed to the next middleware/route handler
    } catch (error) {
        console.error("Token verification failed:", error);
        return res.status(401).json({ message: "Invalid token" });
    }
}


function verifyLogin(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1]; // Extract token from the Authorization header

    if (!token) {
        return res.status(401).json({ message: "No token provided" });
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY); // Verify the token

        req.user = decoded; // Add user data to request for further use
        next(); // Proceed to the next middleware/route handler
    } catch (error) {
        console.error("Token verification failed:", error);
        return res.status(401).json({ message: "Invalid token" });
    }
}

// Start server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
