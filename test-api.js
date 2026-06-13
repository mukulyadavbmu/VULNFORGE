const axios = require('axios');
const dotenv = require('dotenv');
dotenv.config();

async function test() {
  try {
    const res = await axios.post('http://localhost:4000/scan', {
      targetUrl: 'http://example.com'
    }, {
      headers: {
        'x-vulnforge-api-key': process.env.VULNFORGE_API_KEY
      }
    });
    console.log('Success:', res.data);
  } catch (err) {
    if (err.response) {
      console.error('Failed HTTP:', err.response.status, err.response.data);
    } else {
      console.error('Failed Network:', err.message);
    }
  }
}

test();
