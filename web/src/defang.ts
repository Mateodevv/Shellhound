/** Make link-shaped indicators safe to paste into tickets and messages. */
export function defang(value: string, type: string): string {
  let result = value
  if (type === 'url') result = result.replace(/^http(s?):\/\//i, 'hxxp$1://')
  if (type === 'ip' || type === 'domain' || type === 'url') {
    result = result.replace(/\./g, '[.]')
  }
  if (type === 'email') result = result.replace(/\./g, '[.]').replace(/@/g, '[at]')
  return result
}
