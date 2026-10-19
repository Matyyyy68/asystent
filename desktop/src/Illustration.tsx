type IllustrationProps = {
  name: string;
  alt: string;
  group?: 'states' | 'security' | 'phishing' | 'ai' | 'people' | 'infrastructure' | 'installer';
  size?: 'small' | 'medium' | 'large';
};

export function Illustration({ name, alt, group = 'states', size = 'medium' }: IllustrationProps) {
  return <figure className={`illustration illustration-${size}`}>
    <img src={`./media/illustrations/${group}/${name}.png`} alt={alt} loading="lazy" width="512" height="341" />
  </figure>;
}
