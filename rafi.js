const bcrypt = require('bcrypt');

const password = 'Rafi@123';  // The password you used to log in
const hashedPassword = '$2b$10$lWyElfX/vsW1knT9S4h5meO4tskgcdWNrLgngTMO1GjWT7lecqm7C';  // The hashed password from your database

bcrypt.compare(password, hashedPassword, (err, isMatch) => {
  if (err) {
    console.error('Error comparing passwords:', err);
  } else {
    console.log('Password match:', isMatch);
    console.log();
      // Should print true if the password matches
  }
});


// const bcrypt = require('bcrypt');
// const password = 'Rono@123';  // The plaintext password

// // Generate a salt and hash the password
// bcrypt.hash(password, 10, (err, hash) => {
//   if (err) {
//     console.error('Error generating hash:', err);
//   } else {
//     console.log('Generated hash:', hash);
//   }
// });
