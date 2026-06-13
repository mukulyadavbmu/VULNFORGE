const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function checkScans() {
  const scans = await prisma.scan.findMany({ orderBy: { createdAt: 'desc' }, take: 5 });
  console.log('Total recent scans:', scans.length);
  for (const s of scans) {
    console.log(`Scan: ${s.id} | Org: ${s.orgId} | User: ${s.userId} | Time: ${s.createdAt}`);
  }
  await prisma.$disconnect();
}
checkScans();
