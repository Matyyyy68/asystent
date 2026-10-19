type IllustrationProps = {
  name: string;
  alt: string;
  group?: 'empty-states' | 'onboarding' | 'status';
  size?: 'small' | 'medium' | 'large';
};

export function Illustration({ name, alt, group = 'empty-states', size = 'medium' }: IllustrationProps) {
  return <figure className={`illustration illustration-${size}`}>
    <img src={`./media/app/${group}/${name}.webp`} alt={alt} loading="lazy" width="410" height="410" />
  </figure>;
}
