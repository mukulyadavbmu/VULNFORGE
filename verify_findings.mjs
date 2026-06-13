import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  const scanId = '90b35346-dd4f-4c5b-ad1a-a2c6658aa87b';
  
  const findings = await prisma.finding.findMany({
    where: { scanId }
  });

  console.log(JSON.stringify(findings, null, 2));

  const nodes = await prisma.attackNode.count({ where: { scanId } });
  console.log('Total Attack Nodes Generated:', nodes);

  const totalEndpoints = await prisma.scanSurface.count({ where: { scanId } });
  console.log('Total Endpoints Discovered:', totalEndpoints);

  const totalFindings = await prisma.finding.count({ where: { scanId } });
  console.log('Total Findings Persisted:', totalFindings);
}

main().finally(() => prisma.$disconnect());
