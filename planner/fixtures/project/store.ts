// The sensitive effects. `findOne` and `deleteMany` are database operations the
// security-role model already recognizes, so the planner reads them from the graph
// rather than being told about them.

const rows: Map<string, string> = new Map();

export const store = {
  findOne(recordId: string): string | undefined {
    return rows.get(recordId);
  },
  deleteMany(recordId: string): number {
    rows.delete(recordId);
    return 1;
  },
};
