// ponytail: real in-memory SQLite implementing D1Database interface for unit tests

import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { join } from "node:path";

export function createTestDb(): D1Database {
  const db = new DatabaseSync(":memory:");
  const migrationSql = ["0001_init.sql", "0002_hardening.sql"]
    .map((file) => readFileSync(join(process.cwd(), "migrations", file), "utf-8"))
    .join("\n");

  db.exec(migrationSql);

  const createStatement = (sql: string, params: any[] = []): D1PreparedStatement => {
    return {
      bind(...newParams: any[]) {
        return createStatement(sql, newParams);
      },
      async first<T = unknown>(colName?: string): Promise<T | null> {
        const stmt = db.prepare(sql);
        const row = stmt.get(...params) as any;
        if (!row) return null;
        if (colName) return row[colName] ?? null;
        return row as T;
      },
      async all<T = Record<string, unknown>>(): Promise<D1Result<T>> {
        const stmt = db.prepare(sql);
        const rows = stmt.all(...params) as T[];
        return {
          results: rows,
          success: true,
          meta: {
            duration: 0,
            rows_read: rows.length,
            rows_written: 0,
          } as any,
        };
      },
      async run<T = Record<string, unknown>>(): Promise<D1Result<T>> {
        const stmt = db.prepare(sql);
        const info = stmt.run(...params);
        return {
          results: [],
          success: true,
          meta: {
            duration: 0,
            changes: Number(info.changes),
            last_row_id: Number(info.lastInsertRowid),
          } as any,
        };
      },
      async raw<T = unknown[]>(options?: any): Promise<any> {
        const stmt = db.prepare(sql);
        const rows = stmt.all(...params);
        return rows.map((r: any) => Object.values(r));
      },
    } as unknown as D1PreparedStatement;
  };

  return {
    prepare(sql: string) {
      return createStatement(sql);
    },
    async batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> {
      const results: D1Result<T>[] = [];
      for (const stmt of statements) {
        const res = await stmt.all<any>();
        results.push(res);
      }
      return results;
    },
    async exec(sql: string): Promise<D1ExecResult> {
      db.exec(sql);
      return { count: 1, duration: 0 };
    },
    dump(): Promise<ArrayBuffer> {
      throw new Error("dump not implemented in mock");
    },
    withSession(_token?: string) {
      return this;
    },
  } as unknown as D1Database;
}
