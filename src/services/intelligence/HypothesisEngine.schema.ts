// ─── ADDITIVE SCHEMA — Hypothesis model ────────────────────────────
// Append this to prisma/schema.prisma to enable persistent hypotheses.
// This is OPTIONAL — HypothesisEngine works with in-memory store by default.
//
// After adding, run:
//   npx prisma db push
//
// model Hypothesis {
//   id                String   @id @default(uuid())
//   scanId            String
//   type              String   // IDOR, Injection, Auth, SSRF, SensitiveAPI
//   confidence        Float    @default(0)
//   evidence          String   @default("[]")  // JSON array of strings
//   relatedEndpoints  String   @default("[]")  // JSON array of endpoint URLs
//   createdAt         DateTime @default(now())
//   updatedAt         DateTime @updatedAt
//
//   scan              Scan     @relation(fields: [scanId], references: [id])
//
//   @@index([scanId, type])
// }
//
// NOTE: Also add to the Scan model:
//   hypotheses  Hypothesis[]
