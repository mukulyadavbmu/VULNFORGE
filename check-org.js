const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function checkOrg() {
  const orgId = '1f3a3b86-4f19-43ed-843b-04b181448054';
  const org = await prisma.organization.findUnique({ where: { id: orgId } });
  console.log('Org exists:', !!org);
  await prisma.$disconnect();
}
checkOrg();
