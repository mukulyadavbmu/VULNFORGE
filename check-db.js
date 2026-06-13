const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function check() {
  try {
    const users = await prisma.user.findMany();
    const orgs = await prisma.organization.findMany();
    console.log('Users:', users.length);
    console.log('Orgs:', orgs.length);
    if (users.length > 0) console.log('First user:', users[0]);
    if (orgs.length > 0) console.log('First org:', orgs[0]);
  } catch (err) {
    console.error('Failed:', err.message);
  } finally {
    await prisma.$disconnect();
  }
}

check();
