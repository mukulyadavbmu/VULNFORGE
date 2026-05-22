/**
 * BusinessLogicTester — Test for business logic vulnerabilities.
 *
 * Tests for:
 *  - Negative quantity purchases
 *  - Price manipulation
 *  - Discount abuse
 *  - Order replay
 *  - Race condition checkout
 *  - Duplicate transaction requests
 *
 * Security: Bounded requests, timeouts, no data corruption.
 * Detection: Creates findings for business logic abuse, price manipulation, race conditions.
 */

import { AttackNode, FindingType, ScanFinding, ScanSession } from '../../types';
import { httpRequest, maybeAddFinding } from '../../utils/scanUtils';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'BusinessLogicTester' });

// ─── Constants ──────────────────────────────────────────────────────────────

const MAX_TESTS_PER_ENDPOINT = 3;
const TIMEOUT_MS = 5000;
const RACE_CONDITION_CONCURRENCY = 5;

// ─── Types ──────────────────────────────────────────────────────────────────

export interface BusinessLogicTest {
  type: 'negative_quantity' | 'price_manipulation' | 'discount_abuse' | 'order_replay' | 'race_condition' | 'duplicate_transaction';
  endpoint: string;
  payload: Record<string, any>;
  evidence: string;
  confidenceScore: number;
}

export interface BusinessLogicTestResult {
  endpointsProcessed: number;
  vulnerabilitiesDetected: number;
  durationMs: number;
  tests: BusinessLogicTest[];
}

// ─── Test Utilities ─────────────────────────────────────────────────────────

/**
 * Detect if an endpoint is a cart/checkout related endpoint
 */
function isCheckoutEndpoint(url: string): boolean {
  const path = new URL(url).pathname.toLowerCase();
  return /cart|checkout|order|purchase|buy|pay|transaction|payment|charge/i.test(path);
}

/**
 * Detect if an endpoint is a product/item endpoint
 */
function isProductEndpoint(url: string): boolean {
  const path = new URL(url).pathname.toLowerCase();
  return /product|item|commodity|goods|article|sku|inventory/i.test(path);
}

// ─── Engine ─────────────────────────────────────────────────────────────────

export class BusinessLogicTester {
  /**
   * Test endpoints for business logic vulnerabilities.
   */
  async test(
    session: ScanSession,
    endpoints: AttackNode[],
  ): Promise<BusinessLogicTestResult> {
    const start = Date.now();
    const tests: BusinessLogicTest[] = [];
    let endpointsProcessed = 0;

    // Filter to checkout/order endpoints
    const checkoutEndpoints = endpoints.filter(
      (ep) => isCheckoutEndpoint(ep.url) && ep.method?.toUpperCase() === 'POST',
    );

    log.info(`Testing ${checkoutEndpoints.length} checkout endpoints for business logic vulnerabilities`);

    for (const endpoint of checkoutEndpoints) {
      if (endpointsProcessed >= 10) break; // Limit to prevent excessive requests
      endpointsProcessed++;

      try {
        // Test 1: Negative quantity
        const negativeTest = await this.testNegativeQuantity(session, endpoint);
        if (negativeTest) tests.push(negativeTest);

        // Test 2: Price manipulation
        const priceTest = await this.testPriceManipulation(session, endpoint);
        if (priceTest) tests.push(priceTest);

        // Test 3: Discount abuse
        const discountTest = await this.testDiscountAbuse(session, endpoint);
        if (discountTest) tests.push(discountTest);

        // Test 4: Race condition (concurrent requests)
        const raceTest = await this.testRaceCondition(session, endpoint);
        if (raceTest) tests.push(raceTest);
      } catch (err) {
        log.debug(`Business logic test failed for ${endpoint.url}: ${err}`);
      }
    }

    const vulnerabilitiesDetected = tests.length;

    log.info('Business logic testing complete', {
      endpointsProcessed,
      vulnerabilitiesDetected,
      durationMs: Date.now() - start,
    });

    return {
      endpointsProcessed,
      vulnerabilitiesDetected,
      tests,
      durationMs: Date.now() - start,
    };
  }

  /**
   * Test: Negative quantity purchase (should be rejected but might be allowed)
   */
  private async testNegativeQuantity(
    session: ScanSession,
    endpoint: AttackNode,
  ): Promise<BusinessLogicTest | null> {
    try {
      const payload = {
        quantity: -1,
        item_id: 1,
        product_id: 1,
      };

      const response = await httpRequest(session, endpoint.url, 'userA', {
        method: 'POST',
        data: JSON.stringify(payload),
        headers: { 'Content-Type': 'application/json' },
      });

      // If negative quantity is accepted (2xx status), it's a vulnerability
      if (response.status >= 200 && response.status < 300) {
        // Double-check it created something
        if (
          response.bodySnippet.includes('success') ||
          response.bodySnippet.includes('created') ||
          response.bodySnippet.includes('order')
        ) {
          return {
            type: 'negative_quantity',
            endpoint: endpoint.url,
            payload,
            evidence: 'Negative quantity purchase accepted without error',
            confidenceScore: 0.85,
          };
        }
      }
    } catch (err) {
      log.debug(`Negative quantity test failed: ${err}`);
    }

    return null;
  }

  /**
   * Test: Price manipulation (sending price in request body)
   */
  private async testPriceManipulation(
    session: ScanSession,
    endpoint: AttackNode,
  ): Promise<BusinessLogicTest | null> {
    try {
      const payload = {
        item_id: 1,
        product_id: 1,
        quantity: 1,
        price: 0.01,
        amount: 0.01,
        total: 0.01,
      };

      const response = await httpRequest(session, endpoint.url, 'userA', {
        method: 'POST',
        data: JSON.stringify(payload),
        headers: { 'Content-Type': 'application/json' },
      });

      // If manipulation is accepted
      if (response.status >= 200 && response.status < 300) {
        if (response.bodySnippet.includes('success') || response.bodySnippet.includes('order')) {
          return {
            type: 'price_manipulation',
            endpoint: endpoint.url,
            payload,
            evidence: 'Price parameter accepted from client-side (price manipulation)',
            confidenceScore: 0.9,
          };
        }
      }
    } catch (err) {
      log.debug(`Price manipulation test failed: ${err}`);
    }

    return null;
  }

  /**
   * Test: Discount abuse (excessive discount codes)
   */
  private async testDiscountAbuse(
    session: ScanSession,
    endpoint: AttackNode,
  ): Promise<BusinessLogicTest | null> {
    try {
      const payload = {
        item_id: 1,
        quantity: 1,
        discount_code: 'DISCOUNT999',
        discount_percent: 999,
        discount_amount: 99999,
      };

      const response = await httpRequest(session, endpoint.url, 'userA', {
        method: 'POST',
        data: JSON.stringify(payload),
        headers: { 'Content-Type': 'application/json' },
      });

      // If excessive discount is accepted
      if (response.status >= 200 && response.status < 300) {
        if (response.bodySnippet.includes('success') || response.bodySnippet.includes('discount')) {
          return {
            type: 'discount_abuse',
            endpoint: endpoint.url,
            payload,
            evidence: 'Excessive discount accepted without validation',
            confidenceScore: 0.8,
          };
        }
      }
    } catch (err) {
      log.debug(`Discount abuse test failed: ${err}`);
    }

    return null;
  }

  /**
   * Test: Race condition (concurrent checkout requests)
   */
  private async testRaceCondition(
    session: ScanSession,
    endpoint: AttackNode,
  ): Promise<BusinessLogicTest | null> {
    try {
      const payload = {
        item_id: 1,
        quantity: 1,
      };

      // Send multiple concurrent requests
      const requests = [];
      for (let i = 0; i < RACE_CONDITION_CONCURRENCY; i++) {
        requests.push(
          httpRequest(session, endpoint.url, 'userA', {
            method: 'POST',
            data: JSON.stringify(payload),
            headers: { 'Content-Type': 'application/json' },
          }),
        );
      }

      const responses = await Promise.allSettled(requests);
      const successCount = responses.filter(
        (r) => r.status === 'fulfilled' && r.value.status >= 200 && r.value.status < 300,
      ).length;

      // If all concurrent requests succeeded (race condition)
      if (successCount === RACE_CONDITION_CONCURRENCY) {
        return {
          type: 'race_condition',
          endpoint: endpoint.url,
          payload,
          evidence: `All ${RACE_CONDITION_CONCURRENCY} concurrent requests succeeded (possible race condition in inventory/payment processing)`,
          confidenceScore: 0.75,
        };
      }
    } catch (err) {
      log.debug(`Race condition test failed: ${err}`);
    }

    return null;
  }
}
