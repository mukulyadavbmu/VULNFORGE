const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function test() {
  try {
    const scan = await prisma.scan.create({
      data: {
        targetUrl: 'http://example.com',
        status: 'running',
        config: JSON.stringify({}),
      }
    });
    console.log('Success:', scan);
  } catch (err) {
    console.error('Failed to create scan:', err.message, err.code, err.meta);
  } finally {
    await prisma.$disconnect();
  }
}

test();
