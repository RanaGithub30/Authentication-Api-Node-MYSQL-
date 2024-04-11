// controllers/userController.js
const bcrypt = require('bcrypt');
const connection = require('../../db/db');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const { validationResult, check  } = require('express-validator');

exports.registerUser = async (req, res) => {
    try{
         const validationRules = [
            check('name', 'Name is required').notEmpty(),
            check('email', 'Email is required').notEmpty().isEmail(),
            check('password', 'Password is required and must be at least 4 characters').notEmpty().isLength({ min: 4 })
          ];
      
          // Check for validation errors
          await Promise.all(validationRules.map(validation => validation.run(req)));
      
          const errors = validationResult(req);
          if (!errors.isEmpty()) {
            const firstError = errors.array()[0];
            return res.status(400).json({ success: 0, statusCode: 401, msg: firstError.msg });
          }
    
    
        const { name, email, user_name, password, role } = req.body;
    
            // Check if the user already exists
            connection.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
            if (err) {
              console.error('Error querying database:', err.message);
              return res.status(500).json({ message: 'Internal server error' });
            }
      
            if (results.length > 0) {
              return res.status(400).json({ success: 0, statusCode: 403, msg: 'User already exists' });
            }
      
            const otp = generateOTP();
            // sendOTP(email, otp); // Sending Mail
    
            
            // Hash the password
            bcrypt.hash(password, 10, (err, hashedPassword) => {
              if (err) {
                console.error('Error hashing password:', err.message);
                return res.status(500).json({ message: 'Internal server error' });
              }
      
              // Insert a new user into the database
              connection.query('INSERT INTO users (name, email, password, otp) VALUES (?, ?, ?, ?)', 
                [name, email, hashedPassword, otp], (err, results) => {
                  if (err) {
                    console.error('Error inserting user into database:', err.message);
                    return res.status(500).json({ message: 'Internal server error' });
                  }
    
                  return res.status(201).json({ success: 1, statusCode: 200, msg: 'Verification email sent' });
              });
            });
          });
    }
    catch (error) {
        console.error(error);
        if (error.name === 'ValidationError') {
          // Handle validation errors with a more structured response
          const validationErrors = {};
          for (const field in error.errors) {
            validationErrors[field] = error.errors[field].message;
          }
          return res.status(400).json({ message: 'Validation failed', errors: validationErrors });
        }
        res.status(500).json({ message: 'Internal server error' });
      }
    };


    // Verify emails

    exports.verifyEmail = async (req, res) => {
      try{
       const validationRules = [
           check('email', 'Email is required').notEmpty().isEmail(),
           check('otp', 'OTP is required').notEmpty(),
         ];
     
         // Check for validation errors
         await Promise.all(validationRules.map(validation => validation.run(req)));
     
         const errors = validationResult(req);
         if (!errors.isEmpty()) {
           const firstError = errors.array()[0];
           return res.status(400).json({ success: 0, statusCode: 401, msg: firstError.msg });
         }
   
         const { email, otp } = req.body;
   
         // Check if the user already exists
         connection.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
           if (err) {
             console.error('Error querying database:', err.message);
             return res.status(500).json({ message: 'Internal server error' });
           }
     
           if (results.length > 0) {
               // Email found in the database, now verify OTP
               const user = results[0];
   
               if (otp.toString() !== user.otp.toString()) {
                   return res.status(400).json({ success: 0, statusCode: 403, msg: 'Invalid OTP' });
               }
   
               let otp_verify_status = "verified";
               let new_otp= '';
   
               connection.query('UPDATE users set otp = ?, otp_verify_status = ? WHERE email = ?', [new_otp, otp_verify_status, email], (err, results) => {
                   if (err) {
                       console.error('Error updating database:', err.message);
                       return res.status(500).json({ message: 'Internal server error' });
                   }
   
                   return res.status(201).json({ success: 1, statusCode: 200, msg: 'Registered Successfully' });
               });
           }
           else{
               return res.status(400).json({ success: 0, statusCode: 403, msg: 'User Not Found' });
           }
   
         });
      }
      catch (error) {
       console.error(error);
       if (error.name === 'ValidationError') {
         // Handle validation errors with a more structured response
         const validationErrors = {};
         for (const field in error.errors) {
           validationErrors[field] = error.errors[field].message;
         }
         return res.status(400).json({ message: 'Validation failed', errors: validationErrors });
       }
       res.status(500).json({ message: 'Internal server error' });
     }
  };


  /**
 * Login
*/

exports.login = async (req, res) => {
  try{
       const validationRules = [
           check('email', 'Email is required').notEmpty().isEmail(),
           check('password', 'Password is required').notEmpty(),
       ];
 
       // Check for validation errors
       await Promise.all(validationRules.map(validation => validation.run(req)));
   
       const errors = validationResult(req);
       if (!errors.isEmpty()) {
           const firstError = errors.array()[0];
           return res.status(400).json({ success: 0, statusCode: 401, msg: firstError.msg });
       }

       const { email, password } = req.body;

       connection.query('SELECT * FROM users WHERE email = ? AND otp_verify_status = ?', [email, 'verified'], (err, results) => {
           if (err) {
               console.error('Error querying database:', err.message);
               return res.status(500).json({ message: 'Internal server error' });
           }

           if (results.length === 0) {
               // User does not exist or has not verified their email
               return res.status(400).json({ success: 0, statusCode: 401, msg: 'Please verify your email first' });
           }

           // User exists and has verified their email, now compare passwords
           const user = results[0];
           bcrypt.compare(password, user.password, (err, passwordMatch) => {
               if (err) {
                   console.error('Error comparing passwords:', err.message);
                   return res.status(500).json({ message: 'Internal server error' });
               }

               if (!passwordMatch) {
                   // Passwords do not match
                   return res.status(400).json({ success: 0, statusCode: 401, msg: 'Invalid credentials' });
               }

               // Passwords match, generate and return authentication token
               const token = generateAuthToken(user.id);

                // Extract fields to include in the response, excluding otp and password
                const { otp, otp_verify_status, password, deleted_at, remember_token, created_at, updated_at, ...userData } = user;

               return res.status(200).json({ success: 1, statusCode: 200, token: token, data: userData, msg: 'Login successful' });
           });
       });
  }
  catch (error) {
   console.error(error);
   if (error.name === 'ValidationError') {
     // Handle validation errors with a more structured response
     const validationErrors = {};
     for (const field in error.errors) {
       validationErrors[field] = error.errors[field].message;
     }
     return res.status(400).json({ message: 'Validation failed', errors: validationErrors });
   }
   res.status(500).json({ message: 'Internal server error' });
 }
};

/**
 * User Profile Details
*/

exports.userProfileDetails = async (req, res) => {
  try {
      const userDetails = req.user;
      const userId = userDetails.userId;

      const results = await new Promise((resolve, reject) => {
          connection.query('SELECT * FROM users WHERE id = ?', [userId], (err, results) => {
              if (err) {
                  console.error('Error querying database:', err.message);
                  reject(err);
              } else {
                  resolve(results);
              }
          });
      });

      if (results.length === 0) {
          return res.status(404).json({ success: 0, statusCode: 404, msg: 'User not found' });
      }

      const result = results[0];

      return res.status(200).json({ success: 1, statusCode: 200, msg: 'User Details', data: result });
  } catch (error) {
      console.error('Error:', error);
      res.status(500).json({ success: 0, statusCode: 500, msg: 'Internal server error' });
  }
}

/**
 * Resend Otp
*/

exports.resendOtp = async (req, res) => {
  try{
      const validationRules = [
          check('email', 'Email is required').notEmpty().isEmail(),
      ];

      // Check for validation errors
      await Promise.all(validationRules.map(validation => validation.run(req)));
  
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
          const firstError = errors.array()[0];
          return res.status(400).json({ success: 0, statusCode: 401, msg: firstError.msg });
      }

      const { email } = req.body;

      connection.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
          if (err) {
              console.error('Error comparing passwords:', err.message);
              return res.status(500).json({ message: 'Internal server error' });
          }

          if (results.length === 0) {
              // User does not exist or has not verified their email
              return res.status(400).json({ success: 0, statusCode: 401, msg: 'No User Found' });
          }

          const otp = generateOTP();
          // sendOTP(email, otp); // Sending Mail

          connection.query('UPDATE users set otp = ?, otp_verify_status = ? WHERE email = ?', [otp, 'pending', email], (err, results) => {
              if (err) {
                  console.error('Error updating database:', err.message);
                  return res.status(500).json({ message: 'Internal server error' });
              }

              return res.status(201).json({ success: 1, statusCode: 200, msg: 'Please Verify Your Email' });
          });
      });
  }
  catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Internal server error' });
  }
}

exports.forgotPassChange = async (req, res) => {
  try{
     const validationRules = [
         check('email', 'Email is required').notEmpty(),
         check('password', 'password is required').notEmpty(),
     ];

     // Check for validation errors
     await Promise.all(validationRules.map(validation => validation.run(req)));
 
     const errors = validationResult(req);
     if (!errors.isEmpty()) {
         const firstError = errors.array()[0];
         return res.status(400).json({ success: 0, statusCode: 401, msg: firstError.msg });
     }

     //
     let user = await fetchDetails('SELECT * from users WHERE email = ?', req.body.email);
     if(!user){
         return res.status(500).json({ success: 0, statusCode: 403, msg: 'Email Not Fund' });
     }

     let password = req.body.password;

     // Hash the password
     bcrypt.hash(password, 10, (err, hashedPassword) => {
         if (err) {
           console.error('Error hashing password:', err.message);
           return res.status(500).json({ message: 'Internal server error' });
         }
 
         // Insert a new user into the database
         connection.query('UPDATE users set password = ? WHERE email = ?', 
           [hashedPassword, req.body.email], (err, results) => {
             if (err) {
               console.error('Error inserting user into database:', err.message);
               return res.status(500).json({ message: 'Internal server error' });
             }
             return res.status(201).json({ success: 1, statusCode: 200, msg: 'Password Change Successfully' });
         });
       });
  }
  catch (error) {
     console.error(error);
     res.status(500).json({ message: 'Internal server error' });
  } 
}


/**
 * User Profile Edit
*/

exports.userProfileEdit = async (req, res) => {
  try{
       const validationRules = [
           check('name', 'Name is required').notEmpty(),
           check('email', 'Email is required').notEmpty().isEmail(),
           check('role', 'role is required').notEmpty(),
       ];

       // Check for validation errors
       await Promise.all(validationRules.map(validation => validation.run(req)));
   
       const errors = validationResult(req);
       if (!errors.isEmpty()) {
           const firstError = errors.array()[0];
           return res.status(400).json({ success: 0, statusCode: 401, msg: firstError.msg });
       }

       const { name, email, role } = req.body;
       const userDetails = req.user;
       const userId = userDetails.userId;
       
       const details = await fetchDetails(`SELECT * FROM users WHERE id = ?`, userId, 'users', 'users');

       /**
        * update the details
       */

       connection.query('UPDATE users set name = ?, email = ?, role = ? WHERE id = ?', [name, email, role, userId], (err, results) => {
           if (err) {
               console.error('Error updating database:', err.message);
               return res.status(500).json({ message: 'Internal server error' });
           }

           return res.status(201).json({ success: 1, statusCode: 200, msg: 'Profile Updated Successfully' });
       });

  }
  catch (error) {
   console.error(error);
   res.status(500).json({ message: 'Internal server error' });
 } 
}

/**
 * change Password
*/

exports.userPassChange = async (req, res) => {
  try{
      const validationRules = [
          check('password', 'password is required').notEmpty(),
      ];

      // Check for validation errors
      await Promise.all(validationRules.map(validation => validation.run(req)));
  
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
          const firstError = errors.array()[0];
          return res.status(400).json({ success: 0, statusCode: 401, msg: firstError.msg });
      }

      const { password } = req.body;
      const userDetails = req.user;
      const userId = userDetails.userId;

       // Hash the password
      bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
          console.error('Error hashing password:', err.message);
          return res.status(500).json({ message: 'Internal server error' });
        }

        // Insert a new user into the database
        connection.query('UPDATE users set password = ? WHERE id = ?', 
          [hashedPassword, userId], (err, results) => {
            if (err) {
              console.error('Error inserting user into database:', err.message);
              return res.status(500).json({ message: 'Internal server error' });
            }
            return res.status(201).json({ success: 1, statusCode: 200, msg: 'Password Change Successfully' });
        });
      });

  }
  catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Internal server error' });
    } 
}
    
/**
 * Generate OTP
 * @returns 
*/

function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000);
}

/**
 * Send Email
 * @param {*} email 
 * @param {*} otp 
 */
function sendOTP(email, otp) {
    // Create a nodemailer transporter using your email service
    const transporter = nodemailer.createTransport({
        service: 'gmail', // such as 'gmail'
        auth: {
            user: 'sudipwebbersmedia@gmail.com',
            pass: 'pprbqyumiajwecii'
        }
    });

    // Email content
    const mailOptions = {
        from: 'email',
        to: email,
        subject: 'Your One Time Password (OTP)',
        text: `Your OTP for registration is: ${otp}`
    };

    // Send the email
    transporter.sendMail(mailOptions, function(error, info) {
        if (error) {
            console.error(error);
        } else {
            console.log('Email sent: ' + info.response);
        }
    });
}

/**
 * Generate Web Token
*/

const generateAuthToken = (userId) => {
    // Define payload (data to be included in the token)
    const payload = {
        userId: userId
        // Add any additional data you want to include
    };

    // Generate JWT with payload and secret key
    const secretKey = process.env.JWT_SECRET_KEY;
    const token = jwt.sign(payload, 'test', { expiresIn: '24h' }); // Change 'your_secret_key' to your actual secret key and adjust expiration time as needed

    return token;
};

// Function to fetch details from the database based on ID and column name
const fetchDetails = async (sql, id, columnName, tableName) => {
    return new Promise((resolve, reject) => {
        connection.query(sql, [id], (err, results) => {
            if (err) {
                console.error(`Error fetching ${columnName} details:`, err.message);
                reject(err);
            } else {
                resolve(results);
            }
        });
    });
};