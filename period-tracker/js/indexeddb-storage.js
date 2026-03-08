/**
 * IndexedDB Storage Module for Your Cycle Keeper
 * Replaces localStorage with persistent IndexedDB storage
 * Maintains AES-256-GCM encryption with PIN-derived keys
 */

"use strict";

const DB_NAME = "yourcyclekeeper";
const DB_VERSION = 1;
const STORE_NAME = "appdata";

let db = null;

/**
 * Initialize IndexedDB database with schema
 * @returns {Promise<IDBDatabase>}
 */
async function initIndexedDB() {
  return new Promise((resolve, reject) => {
    if (db) {
      resolve(db);
      return;
    }

    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => {
      console.error("❌ IndexedDB init failed:", request.error);
      reject(
        new Error(`IndexedDB initialization failed: ${request.error?.message}`)
      );
    };

    request.onsuccess = () => {
      db = request.result;
      console.log("✅ IndexedDB initialized");
      resolve(db);
    };

    // Schema creation/upgrade
    request.onupgradeneeded = (event) => {
      const database = event.target.result;

      // Create object store if it doesn't exist
      if (!database.objectStoreNames.contains(STORE_NAME)) {
        database.createObjectStore(STORE_NAME);
        console.log("✅ IndexedDB schema created");
      }
    };
  });
}

/**
 * Get a value from IndexedDB by key
 * @param {string} key - The key to retrieve
 * @returns {Promise<any>} The stored value or null
 */
async function getFromDB(key) {
  try {
    await initIndexedDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], "readonly");
      const store = transaction.objectStore(STORE_NAME);
      const request = store.get(key);

      request.onsuccess = () => {
        resolve(request.result !== undefined ? request.result : null);
      };

      request.onerror = () => {
        console.error(`❌ Failed to read key "${key}":`, request.error);
        reject(
          new Error(`Failed to read from database: ${request.error?.message}`)
        );
      };
    });
  } catch (error) {
    console.error("🚨 getFromDB error:", error);
    throw error;
  }
}

/**
 * Set a value in IndexedDB
 * @param {string} key - The key to store
 * @param {any} value - The value to store
 * @returns {Promise<void>}
 */
async function setInDB(key, value) {
  try {
    await initIndexedDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], "readwrite");
      const store = transaction.objectStore(STORE_NAME);
      const request = store.put(value, key);

      request.onsuccess = () => {
        resolve();
      };

      request.onerror = () => {
        console.error(`❌ Failed to write key "${key}":`, request.error);
        reject(
          new Error(`Failed to write to database: ${request.error?.message}`)
        );
      };
    });
  } catch (error) {
    console.error("🚨 setInDB error:", error);
    throw error;
  }
}

/**
 * Delete a key from IndexedDB
 * @param {string} key - The key to delete
 * @returns {Promise<void>}
 */
async function deleteFromDB(key) {
  try {
    await initIndexedDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], "readwrite");
      const store = transaction.objectStore(STORE_NAME);
      const request = store.delete(key);

      request.onsuccess = () => {
        resolve();
      };

      request.onerror = () => {
        console.error(`❌ Failed to delete key "${key}":`, request.error);
        reject(
          new Error(`Failed to delete from database: ${request.error?.message}`)
        );
      };
    });
  } catch (error) {
    console.error("🚨 deleteFromDB error:", error);
    throw error;
  }
}

/**
 * Clear all data from IndexedDB
 * @returns {Promise<void>}
 */
async function clearDB() {
  try {
    await initIndexedDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], "readwrite");
      const store = transaction.objectStore(STORE_NAME);
      const request = store.clear();

      request.onsuccess = () => {
        console.log("✅ IndexedDB cleared");
        resolve();
      };

      request.onerror = () => {
        console.error("❌ Failed to clear database:", request.error);
        reject(
          new Error(`Failed to clear database: ${request.error?.message}`)
        );
      };
    });
  } catch (error) {
    console.error("🚨 clearDB error:", error);
    throw error;
  }
}

/**
 * Get all keys from IndexedDB
 * @returns {Promise<Array<string>>}
 */
async function getAllKeysFromDB() {
  try {
    await initIndexedDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], "readonly");
      const store = transaction.objectStore(STORE_NAME);
      const request = store.getAllKeys();

      request.onsuccess = () => {
        resolve(request.result || []);
      };

      request.onerror = () => {
        console.error("❌ Failed to get keys:", request.error);
        reject(
          new Error(
            `Failed to get keys from database: ${request.error?.message}`
          )
        );
      };
    });
  } catch (error) {
    console.error("🚨 getAllKeysFromDB error:", error);
    throw error;
  }
}

/**
 * Calculate total storage usage in IndexedDB
 * @returns {Promise<number>} Approximate storage size in bytes
 */
async function calculateDBStorageUsage() {
  try {
    if (!navigator.storage || !navigator.storage.estimate) {
      console.warn("⚠️ Storage API not available");
      return 0;
    }

    const estimate = await navigator.storage.estimate();
    return estimate.usage || 0;
  } catch (error) {
    console.error("⚠️ Could not estimate storage usage:", error);
    return 0;
  }
}
