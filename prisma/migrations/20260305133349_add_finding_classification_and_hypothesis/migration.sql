-- CreateTable
CREATE TABLE "Hypothesis" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "scanId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "confidence" REAL NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'active',
    "lastTested" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Hypothesis_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_Finding" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "scanId" TEXT NOT NULL,
    "endpointId" TEXT,
    "url" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "classification" TEXT NOT NULL DEFAULT 'vulnerability',
    "evidence" TEXT NOT NULL,
    "description" TEXT NOT NULL DEFAULT '',
    "reproduction" TEXT NOT NULL DEFAULT '{}',
    "aiExplanation" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Finding_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT "Finding_endpointId_fkey" FOREIGN KEY ("endpointId") REFERENCES "Endpoint" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);
INSERT INTO "new_Finding" ("aiExplanation", "createdAt", "description", "endpointId", "evidence", "id", "reproduction", "scanId", "severity", "type", "url") SELECT "aiExplanation", "createdAt", "description", "endpointId", "evidence", "id", "reproduction", "scanId", "severity", "type", "url" FROM "Finding";
DROP TABLE "Finding";
ALTER TABLE "new_Finding" RENAME TO "Finding";
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;

-- CreateIndex
CREATE INDEX "Hypothesis_scanId_idx" ON "Hypothesis"("scanId");

-- CreateIndex
CREATE INDEX "Hypothesis_scanId_status_idx" ON "Hypothesis"("scanId", "status");
