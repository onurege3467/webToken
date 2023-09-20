export class PathExtractor {
  private static cache = new Map<string, PathToken[]>();

  static extract(payload: any, path: string): any {
    if (!path) return payload;

    const tokens = this.parsePath(path);
    let result = payload;

    for (const token of tokens) {
      if (result == null) {
        return undefined;
      }

      if (token.type === 'property') {
        result = result[token.value];
      } else if (token.type === 'index') {
        const index = parseInt(token.value, 10);
        if (!Array.isArray(result) || index < 0 || index >= result.length) {
          return undefined;
        }
        result = result[index];
      }
    }

    return result;
  }

  static extractWithArray(payload: any, path: string): any {
    if (!path) return payload;

    const regex = /([^\.\[\]]+)|\[(\d+)\]/g;
    let result = payload;

    for (const match of path.matchAll(regex)) {
      if (result == null) {
        return undefined;
      }

      if (match[1]) {
        result = result[match[1]];
      } else if (match[2]) {
        const index = parseInt(match[2], 10);
        if (!Array.isArray(result) || index < 0 || index >= result.length) {
          return undefined;
        }
        result = result[index];
      }
    }

    return result;
  }

  static extractFirst(payload: any, paths: string[]): any {
    if (!paths || paths.length === 0) {
      return undefined;
    }

    for (const path of paths) {
      const result = this.extract(payload, path);
      if (result !== undefined) {
        return result;
      }
    }

    return undefined;
  }

  private static parsePath(path: string): PathToken[] {
    if (this.cache.has(path)) {
      return this.cache.get(path)!;
    }

    const tokens: PathToken[] = [];
    const regex = /([^?.\[\]]+)|\?(\.)|\[(\d+)\]/g;

    for (const match of path.matchAll(regex)) {
      if (match[1]) {
        tokens.push({ type: 'property', value: match[1] });
      } else if (match[3]) {
        tokens.push({ type: 'index', value: match[3] });
      }
    }

    this.cache.set(path, tokens);
    return tokens;
  }
}

interface PathToken {
  type: 'property' | 'index';
  value: string;
}
