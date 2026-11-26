import { Link } from 'react-router-dom';
import { LayoutDashboard, Radar } from 'lucide-react';
import { AppShell } from '../components/AppShell';

/**
 * T50 없는 주소 화면. 화면 경로 목록에 없는 주소를 현황판으로 돌려보내지 않고 여기서 알린다.
 * 요청 주소는 화면에 옮겨 적지 않는다. 화면 자료 API를 부르지 않는다.
 */
export function NotFoundPage() {
  return (
    <AppShell title="페이지를 찾을 수 없습니다">
      <section className="soc-card p-6">
        <p className="text-sm text-slate-300">주소가 바뀌었거나 없는 화면입니다.</p>
        <div className="mt-4 flex flex-wrap gap-2">
          <Link to="/" className="soc-btn-secondary">
            <LayoutDashboard className="h-4 w-4" aria-hidden="true" />
            현황판
          </Link>
          <Link to="/incidents" className="soc-btn-secondary">
            <Radar className="h-4 w-4" aria-hidden="true" />
            인시던트 목록
          </Link>
        </div>
      </section>
    </AppShell>
  );
}
